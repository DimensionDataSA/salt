# -*- coding: utf-8 -*-
'''
Dimension Data Cloud Module 
===========================

This is a cloud module for the Dimension Data Cloud,
using the existing Libcloud driver for Dimension Data.

.. code-block:: yaml

    # Note: This example is for /etc/salt/cloud.providers
    # or any file in the
    # /etc/salt/cloud.providers.d/ directory.

    my-dimensiondata-config:
      user_id: my_username
      key: myPassword!
      region: dd-na
      driver: dimensiondata

:maintainer: Anthony Shaw <anthonyshaw@apache.org>
:depends: libcloud >= 1.2.1
'''

# Import python libs
from __future__ import absolute_import
import logging
import socket
import pprint
import contextlib
import urllib2

# Import salt libs
from salt.utils.validate.net import ipv4_addr as _ipv4_addr

# Import libcloud
try:
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.compute.base import NodeState
    from libcloud.compute.base import NodeAuthPassword
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver
    from libcloud.loadbalancer.base import Member
    from libcloud.loadbalancer.types import Provider as Provider_lb
    from libcloud.loadbalancer.providers import get_driver as get_driver_lb
    # See https://github.com/saltstack/salt/issues/32743
    import libcloud.security
    libcloud.security.CA_CERTS_PATH.append('/etc/ssl/certs/YaST-CA.pem')
    HAS_LIBCLOUD = True
except ImportError:
    HAS_LIBCLOUD = False

# Import generic libcloud functions
# from salt.cloud.libcloudfuncs import *

# Import salt libs
import salt.utils

# Import salt.cloud libs
from salt.cloud.libcloudfuncs import *  # pylint: disable=redefined-builtin,wildcard-import,unused-wildcard-import
from salt.utils import namespaced_function
import salt.utils.cloud
import salt.config as config
from salt.exceptions import (
    SaltCloudSystemExit,
    SaltCloudExecutionFailure,
    SaltCloudExecutionTimeout
)

try:
    from netaddr import all_matching_cidrs  # pylint: disable=unused-import
    HAS_NETADDR = True
except ImportError:
    HAS_NETADDR = False


# Some of the libcloud functions need to be in the same namespace as the
# functions defined in the module, so we create new function objects inside
# this module namespace
get_size = namespaced_function(get_size, globals())
get_image = namespaced_function(get_image, globals())
avail_locations = namespaced_function(avail_locations, globals())
avail_images = namespaced_function(avail_images, globals())
avail_sizes = namespaced_function(avail_sizes, globals())
script = namespaced_function(script, globals())
reboot = namespaced_function(reboot, globals())
list_nodes = namespaced_function(list_nodes, globals())
list_nodes_full = namespaced_function(list_nodes_full, globals())
list_nodes_select = namespaced_function(list_nodes_select, globals())
show_instance = namespaced_function(show_instance, globals())
get_node = namespaced_function(get_node, globals())

# Get logging started
log = logging.getLogger(__name__)

__virtualname__ = 'dimensiondata'


def __virtual__():
    '''
    Set up the libcloud functions and check for dimensiondata configurations.
    '''
    if get_configured_provider() is False:
        return False

    if get_dependencies() is False:
        return False

    for provider, details in six.iteritems(__opts__['providers']):
        if 'dimensiondata' not in details:
            continue

    return __virtualname__


def get_configured_provider():
    '''
    Return the first configured instance.
    '''
    return config.is_provider_configured(
        __opts__,
        __active_provider_name__ or 'dimensiondata',
        ('user_id', 'key', 'region')
    )


def get_dependencies():
    '''
    Warn if dependencies aren't met.
    '''
    deps = {
        'libcloud': HAS_LIBCLOUD,
        'netaddr': HAS_NETADDR
    }
    return config.check_driver_dependencies(
        __virtualname__,
        deps
    )


def create(vm_):
    '''
    Create a single VM from a data dict
    '''
    try:
        # Check for required profile parameters before sending any API calls.
        if vm_['profile'] and config.is_profile_configured(
                __opts__,
                __active_provider_name__ or 'dimensiondata',
                vm_['profile']) is False:
            return False
    except AttributeError:
        pass

    # Since using "provider: <provider-engine>" is deprecated, alias provider
    # to use driver: "driver: <provider-engine>"
    if 'provider' in vm_:
        vm_['driver'] = vm_.pop('provider')

    __utils__['cloud.fire_event'](
        'event',
        'starting create',
        'salt/cloud/{0}/creating'.format(vm_['name']),
        args={
            'name': vm_['name'],
            'profile': vm_['profile'],
            'provider': vm_['driver'],
        },
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )

    log.info('Creating Cloud VM %s', vm_['name'])
    conn = get_conn()
    rootPw = NodeAuthPassword(vm_['auth'])
    network_domain = ''

    try:
        location = conn.ex_get_location_by_id(vm_['location'])
        images = conn.list_images(location=location)
        image = [x for x in images if x.id == vm_['image']][0]
        network_domains = conn.ex_list_network_domains(location=location)
        try:
            network_domain = [y for y in network_domains
                              if y.name == vm_['network_domain']][0]
        except IndexError:
            network_domain = conn.ex_create_network_domain(
                location=location,
                name=vm_['network_domain'],
                plan='ADVANCED',
                description=''
            )

        try:
            vlan = [y for y in conn.ex_list_vlans(
                location=location,
                network_domain=network_domain)
                    if y.name == vm_['vlan']][0]
        except (IndexError, KeyError):
            # Use the first VLAN in the network domain
            try:
              vlan = conn.ex_create_vlan(
                       network_domain=network_domain,
                       name=vm_['vlan'],
                       private_ipv4_base_address='192.168.1.0',
                       description='Created by SaltStack',
                       private_ipv4_prefix_size=24)
            except DimensionDataAPIException as dexec:
                if dexec.msg.find('RESOURCE_BUSY'):
                    log.error(
                        'Error creating VLAN %s on DIMENSIONDATA\n\n'
                        'The following exception was thrown by libcloud when trying to '
                        'run the initial deployment: \n%s',
                        vm_['vlan'], exc,
                        exc_info_on_loglevel=logging.DEBUG
                    )
                    return False

        kwargs = {
            'name': vm_['name'],
            'image': image,
            'auth': rootPw,
            'ex_description': vm_['description'],
            'ex_network_domain': network_domain,
            'ex_vlan': vlan,
            'ex_is_started': vm_['is_started']
        }
        data = conn.create_node(**kwargs)
    except Exception as exc:
        log.error(
            'Error creating %s on DIMENSIONDATA\n\n'
            'The following exception was thrown by libcloud when trying to '
            'run the initial deployment: \n%s',
            vm_['name'], exc,
            exc_info_on_loglevel=logging.DEBUG
        )
        return False

    data = salt.utils.cloud.wait_for_fun(
        _configure_network,
        timeout=config.get_cloud_config_value(
            'wait_for_ip_timeout', vm_, __opts__, default=25 * 60),
        interval=config.get_cloud_config_value(
            'wait_for_ip_interval', vm_, __opts__, default=30),
        max_failures=config.get_cloud_config_value(
            'wait_for_ip_max_failures', vm_, __opts__, default=60),)

    data = salt.utils.cloud.wait_for_ip(
        __query_node_data,
        update_args=(vm_, data),
        timeout=config.get_cloud_config_value(
            'wait_for_ip_timeout', vm_, __opts__, default=25 * 60),
        interval=config.get_cloud_config_value(
            'wait_for_ip_interval', vm_, __opts__, default=30),
        max_failures=config.get_cloud_config_value(
            'wait_for_ip_max_failures', vm_, __opts__, default=60),
    )

    def __query_node_data(vm_, data):
        running = False
        try:
            node = show_instance(vm_['name'], 'action')
            running = (node['state'] == NodeState.RUNNING)
            log.debug(
                'Loaded node data for %s:\nname: %s\nstate: %s',
                vm_['name'],
                pprint.pformat(node['name']),
                node['state']
                )
        except Exception as err:
            log.error(
                'Failed to get nodes list: %s', err,
                # Show the traceback if the debug logging level is enabled
                exc_info_on_loglevel=logging.DEBUG
            )
            # Trigger a failure in the wait for IP function
            return False

        if not running:
            # Still not running, trigger another iteration
            return

        private = node['private_ips']
        public = node['public_ips']

        if private and not public:
            log.warning(
                'Private IPs returned, but not public... Checking for '
                'misidentified IPs'
            )
            for private_ip in private:
                private_ip = preferred_ip(vm_, [private_ip])
                if salt.utils.cloud.is_public_ip(private_ip):
                    log.warning('%s is a public IP', private_ip)
                    data.public_ips.append(private_ip)
                else:
                    log.warning('%s is a private IP', private_ip)
                    if private_ip not in data.private_ips:
                        data.private_ips.append(private_ip)

            if ssh_interface(vm_) == 'private_ips' and data.private_ips:
                return data

        if private:
            data.private_ips = private
            if ssh_interface(vm_) == 'private_ips':
                return data

        if public:
            data.public_ips = public
            if ssh_interface(vm_) != 'private_ips':
                return data

    try:
        data = salt.utils.cloud.wait_for_ip(
            __query_node_data,
            update_args=(vm_, data),
            timeout=config.get_cloud_config_value(
                'wait_for_ip_timeout', vm_, __opts__, default=25 * 60),
            interval=config.get_cloud_config_value(
                'wait_for_ip_interval', vm_, __opts__, default=30),
            max_failures=config.get_cloud_config_value(
                'wait_for_ip_max_failures', vm_, __opts__, default=60),
        )
    except (SaltCloudExecutionTimeout, SaltCloudExecutionFailure) as exc:
        try:
            # It might be already up, let's destroy it!
            destroy(vm_['name'])
        except SaltCloudSystemExit:
            pass
        finally:
            raise SaltCloudSystemExit(str(exc))

    log.debug('VM is now running')
    if ssh_interface(vm_) == 'private_ips':
        ip_address = preferred_ip(vm_, data.private_ips)
    else:
        ip_address = preferred_ip(vm_, data.public_ips)
    log.debug('Using IP address %s', ip_address)

    if salt.utils.cloud.get_salt_interface(vm_, __opts__) == 'private_ips':
        salt_ip_address = preferred_ip(vm_, data.private_ips)
        log.info('Salt interface set to: %s', salt_ip_address)
    else:
        salt_ip_address = preferred_ip(vm_, data.public_ips)
        log.debug('Salt interface set to: %s', salt_ip_address)

    if not ip_address:
        raise SaltCloudSystemExit(
            'No IP addresses could be found.'
        )

    vm_['salt_host'] = salt_ip_address
    vm_['ssh_host'] = ip_address
    vm_['password'] = vm_['auth']

    ret = __utils__['cloud.bootstrap'](vm_, __opts__)

    ret.update(data.__dict__)

    if 'password' in data.extra:
        del data.extra['password']

    log.info('Created Cloud VM \'{0[name]}\''.format(vm_))
    log.debug(
        '\'{0[name]}\' VM creation details:\n{1}'.format(
            vm_, pprint.pformat(data.__dict__)
        )
    )

    __utils__['cloud.fire_event'](
        'event',
        'created instance',
        'salt/cloud/{0}/created'.format(vm_['name']),
        args={
            'name': vm_['name'],
            'profile': vm_['profile'],
            'provider': vm_['driver'],
        },
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )

    return ret

def destroy(name, call=None):
    '''
    Destroy a node. Will check termination protection and warn if enabled.
    CLI Example:
    .. code-block:: bash
        salt-cloud --destroy mymachine
    '''
    conn = get_conn()
    
    if call == 'function':
        raise SaltCloudSystemExit(
            'The destroy action must be called with -d, --destroy, '
            '-a or --action.'
        )

    __utils__['cloud.fire_event'](
        'event',
        'destroying instance',
        'salt/cloud/{0}/destroying'.format(name),
        args={'name': name},
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )

    data = show_instance(name, call='action')
    log.debug(data)
    log.warning('%s will be destroyed', name)
    
    node = conn.ex_get_node_by_id(data['id'])
    try:
    	if data['state'] != 'stopped':
    		log.info('First stopping node %s', name)
    		ret = conn.ex_shutdown_graceful(node)
    		conn.ex_wait_for_state('stopped',conn.ex_get_node_by_id, 10, 120, data['id'])
    except Exception as exc:
    	log.error(
            'Error stopping %s on DIMENSIONDATA\n\n'
            'The following exception was thrown by libcloud when trying to '
            'run the initial deployment: \n%s',
            name, exc,
            exc_info_on_loglevel=logging.DEBUG
        )
        log.warning('Destroying node %s optimistically', name)
      	pass
    
    try:
    	ret = conn.destroy_node(node)
    except Exception as exc:
        log.error(
            'Error destroying %s on DIMENSIONDATA\n\n'
            'The following exception was thrown by libcloud when trying to '
            'run the initial deployment: \n%s',
            name, exc,
            exc_info_on_loglevel=logging.DEBUG
        )
        return False
	

    __utils__['cloud.fire_event'](
        'event',
        'destroyed instance',
        'salt/cloud/{0}/destroyed'.format(name),
        args={'name': name},
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )

    if __opts__.get('update_cachedir', False) is True:
        __utils__['cloud.delete_minion_cachedir'](name, __active_provider_name__.split(':')[0], __opts__)

    return ret

def create_lb(kwargs=None, call=None):
    r'''
    Create a load-balancer configuration.
    CLI Example:

    .. code-block:: bash

        salt-cloud -f create_lb dimensiondata \
            name=dev-lb port=80 protocol=http \
            members=w1,w2,w3 algorithm=ROUND_ROBIN
    '''
    conn = get_conn()
    if call != 'function':
        raise SaltCloudSystemExit(
            'The create_lb function must be called with -f or --function.'
        )

    if not kwargs or 'name' not in kwargs:
        log.error(
            'A name must be specified when creating a health check.'
        )
        return False
    if 'port' not in kwargs:
        log.error(
            'A port or port-range must be specified for the load-balancer.'
        )
        return False
    if 'networkdomain' not in kwargs:
        log.error(
            'A network domain must be specified for the load-balancer.'
        )
        return False
    if 'members' in kwargs:
        members = []
        ip = ""
        membersList = kwargs.get('members').split(',')
        log.debug('MemberList: %s', membersList)
        for member in membersList:
            try:
                log.debug('Member: %s', member)
                node = get_node(conn, member)
                log.debug('Node: %s', node)
                ip = node.private_ips[0]
            except Exception as err:
                log.error(
                    'Failed to get node ip: %s', err,
                    # Show the traceback if the debug logging level is enabled
                    exc_info_on_loglevel=logging.DEBUG
                )
            members.append(Member(ip, ip, kwargs['port']))
    else:
        members = None
    log.debug('Members: %s', members)

    networkdomain = kwargs['networkdomain']
    name = kwargs['name']
    port = kwargs['port']
    protocol = kwargs.get('protocol', None)
    algorithm = kwargs.get('algorithm', None)

    lb_conn = get_lb_conn(conn)
    network_domains = conn.ex_list_network_domains()
    network_domain = [y for y in network_domains if y.name == networkdomain][0]

    log.debug('Network Domain: %s', network_domain.id)
    lb_conn.ex_set_current_network_domain(network_domain.id)

    __utils__['cloud.fire_event'](
        'event',
        'create load_balancer',
        'salt/cloud/loadbalancer/creating',
        args=kwargs,
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )

    lb = lb_conn.create_balancer(
        name, port, protocol, algorithm, members
    )

    __utils__['cloud.fire_event'](
        'event',
        'created load_balancer',
        'salt/cloud/loadbalancer/created',
        args=kwargs,
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )
    return _expand_balancer(lb)

def _configure_network():
      '''
      Configure the Dimension Data network for remote/external connectivity from Salt Cloud client
      '''
      if(ssh_interface(vm_) == 'public_ips'):
        ext_ip_addr = _get_ext_ip()
        if(ext_ip_addr.external_ip == ''):
            destroy(vm_['name'])
            return False
        if(_setup_remote_salt_access(network_domain, vm_, conn).status is False):
            destroy(vm_['name'])
            return False

def _setup_remote_salt_access(network_domain, vm_, connection):
    '''
    Configure network for public IP and firewall rules
    :param connection: Provider connection
    :return: string Public IP
    '''

    node = show_instance(vm_['name'], 'action')
    private_ips = node['private_ips']
    log.info('Creating NAT Rule for VM {0}'.format(vm_['name']))
    try:
      nat_resp = connection.ex_create_nat_rule(network_domain, private_ips[0])
      public_ip = nat_resp.external_ip
    except Exception as exc:
      log.error(
          'Error creating NAT rule on DIMENSIONDATA\n\n'
          'The following exception was thrown by libcloud when trying to '
          'run the initial deployment: \n%s',
          vm_['name'], exc,
          exc_info_on_loglevel=logging.DEBUG
      )
      return {'status': False, 'public_ip': ''}

    try:
        ip_addr_list = connection.ex_get_ip_address_list(network_domain, 'Salt_Minions_SSH_201611')
        log.info('Creating IP Address List for VM {0}'.format(vm_['name']))
        if ip_addr_list:
          ip_addr_list_create = connection.ex_create_ip_address_list(network_domain, 'Salt_Minions_SSH_201611', \
                                                                     'Created by SaltStack', 'IPV4', \
                                                                     DimensionDataIpAddress(begin=private_ips[0]))
          ip_addr_list_id = ip_addr_list_create.id
        else:
          ip_addr_col = ip_addr_list.ip_address_collection
          ip_addr_list_mod = connection.ex_edit_ip_address_list(ex_ip_address_list=ip_addr_list.id, \
                                                                ip_address_collection=ip_addr_col.add(DimensionDataIpAddress(begin=private_ips[0])))
    except Exception as exc:
        log.error(
              'Error creating or modifying IP address list on DIMENSIONDATA\n\n'
              'The following exception was thrown by libcloud when trying to '
              'run the initial deployment: \n%s',
              vm_['name'], exc,
              exc_info_on_loglevel=logging.DEBUG
        )
        return {'status': False, 'public_ip': ''}

    try:
        log.info('Creating Firewall Rules for VM {0}'.format(vm_['name']))
        fw_rules = connection.ex_list_firewall_rules(network_domain)
        fw_rule = (list(filter(lambda x: x.name == 'Salt_SSH_Minion_FW_Rule_201611', firewall_rules))[0])
        if fw_rule:
         fw_resp = connection.ex_create_firewall_rule(network_domain, DimensionDataFirewallRule(name='Salt_SSH_Minion_FW_Rule_201611',\
                                                                                                network_domain=network_domain,\
                                                                                                ip_version='IPV4',\
                                                                                                protocol='TCP',\
                                                                                                source=DimensionDataFirewallAddress(\
                                                                                                    ip_address=public_ip),\
                                                                                                location='FIRST',\
                                                                                                action='ACCEPT_DECISIVELY',\
                                                                                                enabled='true',\
                                                                                                destination=DimensionDataFirewallAddress(\
                                                                                                    ip_address_list=ip_addr_list_id,\
                                                                                                    port_begin='22')),\
                                                                                                'FIRST')

    except Exception as exc:
        log.error(
              'Error creating Firewall Rule on DIMENSIONDATA\n\n'
              'The following exception was thrown by libcloud when trying to '
              'run the initial deployment: \n%s',
              vm_['name'], exc,
              exc_info_on_loglevel=logging.DEBUG
        )
        return {'status': False, 'public_ip': ''}

    return {'status': True, 'public_ip': public_ip}

def _expand_balancer(lb):
    '''
    Convert the libcloud load-balancer object into something more serializable.
    '''
    ret = {}
    ret.update(lb.__dict__)
    return ret

def _get_ext_ip():
    '''
    Return external IP of the host (master) executing salt-cloud
    :return: json external IP
    '''
    log.info('Determining external IP...')

    check_ips = ('http://ipecho.net/plain',
                 'http://v4.ident.me')

    for url in check_ips:
        try:
            with contextlib.closing(urllib2.urlopen(url, timeout=3)) as req:
                ip_ = req.read().strip()
                if not _ipv4_addr(ip_):
                    continue
            return {'external_ip': ip_}
        except (urllib2.HTTPError,
                urllib2.URLError,
                socket.timeout):
            log.error(
                'Error detecting external IP address\n\n'
                'The following exception was thrown during checking external IP of this machine ',
                urllib2.HTTPError, urllib2.URLError, socket.timeout,
                exc_info_on_loglevel=logging.DEBUG
            )
            continue
    # Return an empty value as a last resort
    return {'external_ip': []}


def preferred_ip(vm_, ips):
    '''
    Return the preferred Internet protocol. Either 'ipv4' (default) or 'ipv6'.
    '''
    proto = config.get_cloud_config_value(
        'protocol', vm_, __opts__, default='ipv4', search_global=False
    )
    family = socket.AF_INET
    if proto == 'ipv6':
        family = socket.AF_INET6
    for ip in ips:
        try:
            socket.inet_pton(family, ip)
            return ip
        except Exception:
            continue
    return False


def ssh_interface(vm_):
    '''
    Return the ssh_interface type to connect to. Either 'public_ips' (default)
    or 'private_ips'.
    '''
    return config.get_cloud_config_value(
        'ssh_interface', vm_, __opts__, default='public_ips',
        search_global=False
    )


def stop(name, call=None):
    '''
    Stop a VM in DimensionData.

    name:
        The name of the VM to stop.

    CLI Example:

    .. code-block:: bash

        salt-cloud -a stop vm_name
    '''
    conn = get_conn()
    node = get_node(conn, name)
    log.debug('Node of Cloud VM: %s', node)

    status = conn.ex_shutdown_graceful(node)
    log.debug('Status of Cloud VM: %s', status)

    return status


def start(name, call=None):
    '''
    Stop a VM in DimensionData.

    :param str name:
        The name of the VM to stop.

    CLI Example:

    .. code-block:: bash

        salt-cloud -a stop vm_name
    '''

    conn = get_conn()
    node = get_node(conn, name)
    log.debug('Node of Cloud VM: %s', node)

    status = conn.ex_start_node(node)
    log.debug('Status of Cloud VM: %s', status)

    return status


def get_conn():
    '''
    Return a conn object for the passed VM data
    '''
    vm_ = get_configured_provider()
    driver = get_driver(Provider.DIMENSIONDATA)

    region = config.get_cloud_config_value(
         'region', vm_, __opts__
    )

    user_id = config.get_cloud_config_value(
        'user_id', vm_, __opts__
    )
    key = config.get_cloud_config_value(
        'key', vm_, __opts__
    )

    if key is not None:
        log.debug('DimensionData authenticating using password')

    return driver(
        user_id,
        key,
        region=region
    )


def get_lb_conn(dd_driver=None):
    '''
    Return a load-balancer conn object
    '''
    vm_ = get_configured_provider()

    region = config.get_cloud_config_value(
        'region', vm_, __opts__
    )

    user_id = config.get_cloud_config_value(
       'user_id', vm_, __opts__
    )
    key = config.get_cloud_config_value(
       'key', vm_, __opts__
    )
    if not dd_driver:
        raise SaltCloudSystemExit(
            'Missing dimensiondata_driver for get_lb_conn method.'
        )
    return get_driver_lb(Provider_lb.DIMENSIONDATA)(user_id, key, region=region)
