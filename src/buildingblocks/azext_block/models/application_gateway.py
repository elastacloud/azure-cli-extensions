from msrestazure.tools import resource_id

from azure.mgmt.network.models import (
    SubResource,
    ApplicationGateway as ApplicationGatwaySdk,
    ApplicationGatewaySkuName,
    ApplicatioNGatewayTier,
    ApplicationGatewaySslProtocol,
    ApplicationGatewayProtocol,
    ApplicationGatewayCookieBasedAffinity,
    ApplicationGatewaySslProtocol,
    ApplicationGatewaySslPolicyType,
    ApplicationGatewaySslPolicyName,
    ApplicationGatewaySslCipherSuite,
    ApplicationGatewayRequestRoutingRuleType,
    ApplicationGatewayRedirectType,
    ApplicationGatewayFirewallMode
)

from .building_block_settings import (BuildingBlock,
                                      RegisterBuildingBlock)
from .resources import (Resource,
                        ResourceId,
                        TaggedResource,
                        TopLevelResource,
                        convert_string_to_enum,
                        extract_resource_groups)
from ..validations import ValidationFunction

from ..validations.networking import (is_valid_port_range)



@RegisterBuildingBlock(name='ApplicationGateway', template_url='buildingBlocks/applicationGateways/applicationGateways.json', deployment_name='agws')
class ApplicationGatewayBuildingBlock(BuildingBlock):
    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[ApplicationGateway]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(ApplicationGatewayBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    def transform(self):
        application_gateways = [application_gateway.transform() for application_gateway in self.settings]

        resource_groups = extract_resource_groups(application_gateways)
        template_parameters = {
            'applicationGateways': application_gateways,
            'publicIpAddresses': None
        }
        return resource_groups, template_parameters

    @classmethod
    def onregister(cls):
        cls.register_sdk_model(ApplicationGatwaySdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}#
        })

@ResourceId(namespace="Microsoft.Network", type="ApplicationGateways")
class ApplicationGateway(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        "sku": {"key": "sku", "type": "Sku"},
        "gateway_ip_configurations": {"key": "gatewayIPConfigurations", "type": "[GatewayIPConfiguration]"},
        "frontend_ip_configurations": {"key": "frontendIPConfigurations", "type": "[FrontendIPConfiguration]"},
        "backend_address_pools": {"key": "backendAddressPools", "type": "[BackendAddressPool]"},
        "backend_http_settings_collection": {"key": "backendHttpSettingsCollection", "type": "[BackendHttpSettings]"},
        "http_listeners": {"key": "httpListeners", "type": "[HttpListener]"},
        "redirect_configurations": {"key": "redirectConfigurations", "type": "RedirectConfiguration]"},
        "url_path_maps": {"key": "urlPathMaps", "type": "[UrlPathMap]"},
        "request_routing_rules": {"key": "requestRoutingRules", "type": "[RequestRoutingRules]"},
        "web_application_firewall_configuration": {"key": "webApplicationFirewallConfiguration", "type": "WebApplicationFirewallConfiguration"},
        "probes": {"key": "probes", "type": "[Probes"},
        "ssl_certificates": {"key": "sslCertificates", "type": "[SslCertificate]"},
        "authentication_certificate": {"key": "authenticationCertificate", "type": "[AuthenticationCertificate]"},
        "frontend_ports": {"key": "frontendPorts", "type": "[FrontendPort]"},
        "ssl_policy": {"key": "sslPolicy", "type": "SslPolicy"}
    }

    def __init__(self, sku=None, gateway_ip_configurations=None, frontend_ip_configurations=None, backend_address_pools=None, backend_http_settings_collection=None, http_listeners=None, redirect_configurations=None, url_path_maps=None, request_routing_rules=None, web_application_firewall_configuration=None, probes=None, ssl_certificates=None, authentication_certificate=None, frontend_ports=None, ssl_policy=None, **kwargs):
         super(ApplicationGateway, self).__init__(**kwargs)
         self.sku = sku if sku else None
         self.gateway_ip_configurations = gateway_ip_configurations if gateway_ip_configurations else None
         self.frontend_ip_configurations = frontend_ip_configurations if frontend_ip_configurations else None
         self.backend_address_pools = backend_address_pools if backend_address_pools else None
         self.backend_http_settings_collection = backend_http_settings_collection if backend_http_settings_collection else None
         self.http_listeners = http_listeners if http_listeners else None
         self.redirect_configurations = redirect_configurations else None
         self.url_path_maps = url_path_maps if url_path_maps else None
         self.request_routing_rules = request_routing_rules if request_routing_rules else None
         self.web_application_firewall_configuration = web_application_firewall_configuration if web_application_firewall_configuration else None
         self.probes = probes if probes else None
         self.ssl_certificates = ssl_certificates else None
         self.authentication_certificate = authentication_certificate else None
         self.frontend_ports = frontend_ports if frontend_ports else None
         self.ssl_policy = ssl_policy if ssl_policy else None
         self._validation.update({
             "sku": {"required": True},
             "gateway_ip_configurations": {"required": True, "min_items": 1},
             "frontend_ip_configurations": {"required": True, "min_items": 1},
             "backend_address_pools": {"required": True, "min_items": 1},
             "backend_http_settings_collection": {"required": True, "min_items": 1},
             "http_listeners": {"required": True, "min_items": 1},
             "redirect_configurations": {"required": True, "min_items": 1},
             "url_path_maps": {"required": True, "min_items": 1},
             "requesting_routing_rules": {"required": True, "min_items": 1},
             "web_application_firewall_configuration": {"required": True},
             "probes": {"required": True, "min_items": 1},
             "ssl_certificates": {"required": True, "min_items": 1},
             "frontend_ports": {"required": True, "min_items": 1}
         })

    def transform(self):

class Sku():
    _attribute_map = {
        "size": {"key": "size", "type": "str"},
        "capacity": {"key": "capacity", "type": "int"},
        "tier": {"key": "tier", "type": "str"}
    }

    _valid_sizes = frozenset([e.value for e in ApplicationGatewaySkuName])
    _valid_tiers = frozenset([e.value for e in ApplicatioNGatewayTier])

    def __init__(self, size=None, capacity=None, tier=None, **kwargs)
         super(Sku, self).__init__(**kwargs)
         self.size = size if size else None
         self.capacity = capacity if capacity else None
         self.tier = tier if tier else None
         self._validation.update({
             "size": {"required": True, "custom": Sku._is_valid_sku},
             "capacity": {"required": True, "custom": Sku._is_valid_capacity},
             "tier": {"required": True, "custom": Sku._is_valid_tier}
         })

    def transform(self):

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_sizes)))
    def _is_valid_sku(self, value):
        if value in cls._valid_sizes:
            return True
        else:
            return False
        
    @ValidationFunction()
    def _is_valid_capacity(self, value):
        if value > 0 and value <= 10:
            return True
        else:
            return False

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_tiers)))
    def _is_valid_tier(self, value):
        if value in cls._valid_tiers:
            return True
        else:
            return False

class GatewayIPConfiguration():
    _attribute_map = {
        "subnet_name": {"key": "subnetName", "type": "str"}
    }

    def __init__(self, subnet_name=None, **kwargs):
         super(GatewayIPConfiguration, self).__init__(**kwargs)
         self.subnet_name = subnet_name if subnet_name else None

         self._validation.update({
             "subnet_name": {"required": True}
         })

    def transform(self):

class FrontEndIPConfiguration():
    _attribute_map = {
        "application_gateway_type": {"key": "applicationGatewayType": "type": "str"},
        "internal_application_gateway_settings": {"key": "internalApplicationGatewaySettings", "type": "[InternalApplicationGatewaySetting]"}
    }
    
    def __init__(self, application_gateway_type=None, internal_application_gateway_settings=None, **kwargs):
        super(FrontEndIPConfiguration, self).__init__(**kwargs)
        self.application_gateway_type = application_gateway_type if application_gateway_type else None
        self.internal_application_gateway_settings = internal_application_gateway_settings if internal_application_gateway_settings else None
        self._validation.update({
            "application_gateway_type": {"required": True, "custom": FrontEndIPConfiguration._is_valid_gateway_type}
        })

    def transform(self):

    @ValidationFunction('Value must be one of the following values: Public, Internal')
    def _is_valid_gateway_type(self, value)
        types = ["Public", "Internal"]

        if value in types:
            return True
        else:
            return False

class InternalApplicationGatewaySetting():
    _attribute_map = {
        "subnet_name": {"key": "subnetName", "type": "str"}
    }

    def __init__(self, subnet_name=None, **kwargs):
         super(InternalApplicationGatewaySetting, self).__init__(**kwargs)
         self.subnet_name = subnet_name if subnet_name else None
         self._validation.update({
             "subnet_name": {"required": True}
         })

    def transform(self):

class BackendAddressPool():

    _attribute_map = {
        "backend_addresses": {"key": "backendAddresses", "type": "[BackendAddress]"}
    }

    def __init__(self, backend_addresses=None, **kwargs)
         super(BackendAddressPool, self).__init__(**kwargs)
         self.backend_addresses = backend_addresses if backend_addresses else None
         self._validation.update({
             "backend_addresses": {"required": True, "min_items": 1}
         })

    def transform(self):

class BackendAddress():
    _attribute_map = {
        "fqdn": {"key": "fqdn", "type": "str"},
        "ip_address": {"key": "ipAddress", "str"}
    }

    def __init__(self, fqdn=None, ip_address=None, **kwargs):
         super(BackendAddress, self).__init__(**kwargs)
         self.fqdn = fqdn if fqdn else None
         self.ip_address if ip_address else None
         self._validation.update({
            # Todo
         })

    def transform(self):

class BackendHttpSettings():
    _attribute_map = {
        "port": {"key": "port", "type": "int"},
        "protocol": {"key": "protocol", "type": "str"},
        "cookie_based_affinity": {"key": "cookieBasedAffinity", "type": "str"},
        "affinity_cookie_name": {"key": "affinityCookieName", "type": "str"},
        "connection_draining": {"key": "connection_draining", "type": "ConnectionDraining"},
        "pick_host_name_from_backend_address": {"key": "pickHostNameFromBackendAddress", "type": "bool"},
        "host_name": {"key": "hostName", "type": "str"},
        "request_timeout": {"key": "requestTimeout", "type": "int"},
        "path": {"key": "path", "type": "str"},
        "host_header_name": {"key": "hostHeaderName", "type": "str"},
        "probe_enabled": {"key": "probeEnabled", "type": "bool"},
        "probe_name": {"key": "probeName", "type": "str"}
    }

     _valid_affinity = frozenset([e.value for e in ApplicationGatewayCookieBasedAffinity])

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_affinity)))
    def _is_valid_cookie_based_affinity(self, value)
        
        if value in cls._valid_affinity:
            return True
        else:
            return False

    @ValidationFunction('Value must be one of the following values: Http, Https')
    def _is_valid_protocol(self, value)
        types = ["Http", "Https"]

        if value in types:
            return True
        else:
            return False

    def __init__(self, port=None, protocol=None, cookie_based_affinity=None, affinity_cookie_name=None, connection_draining=None, pick_host_name_from_backend_address=None, host_name=None, request_timeout=None, path=None, host_header_name=None, probe_enabled=None, probe_name=None, **kwargs):
         super(BackendHttpSettings, self).__init__(**kwargs)
         self.port = port if port else None
         self.protocol = protocol if protocol else None
         self.cookie_based_affinity = cookie_based_affinity if cookie_based_affinity else None
         self.affinity_cookie_name = affinity_cookie_name if affinity_cookie_name else None
         self.connection_draining = connection_draining if connection_draining else None
         self.pick_host_name_from_backend_address = pick_host_name_from_backend_address if pick_host_name_from_backend_address else None
         self.host_name = host_name if host_name else None
         self.request_timeout = request_timeout if request_timeout else None
         self.path = path if path else None
         self.host_header_name = host_header_name if host_header_name else None
         self.probe_enabled = probe_enabled if probe_enabled else None
         self.probe_name = probe_name if probe_name else None
         self._validation.update({
            "port": {"required": True, "custom": is_valid_port_range},
            "protocol": {"required": True, "custom": cls._is_valid_protocol},
            "cookie_based_affinity": {"required": True, "custom": cls._is_valid_cookie_based_affinity}
            #HERE
         })

    def transform(self):

class ConnectionDraining():
    _attribute_map = {
        "enabled": {"key": "enabled", "type": "bool"},
        "drain_timeout_in_sec": {"key": "drainTimeoutInSec", "type": "int"}
    }

    def __init__(self, enabled=None, drain_timeout_in_sec=None, **kwargs)
         super(ConnectionDraining, self).__init__(**kwargs)

class HttpListener():
    _attribute_map = {
        "frontend_ip_configuration_name": {"key": "frontendIPConfigurationName", "type": "str"},
        "frontend_port_name": {"key": "frontendPortName", "type": "str"},
        "protocol": {"key": "protocol", "type": "str"},
        "ssl_certificate_name": {"key": "sslCertificateName", "type": "str"},
        "require_server_name_indication": {"key", "requireServerNameIndication", "type": "bool"}
    }

    def __init__(self, frontend_ip_configuration_name=None, frontend_port_name=None, protocol=None, ssl_certificate_name=None, require_server_name_indication=None, **kwargs):
         super(HttpListener, self).__init__(**kwargs)

    def transform(self):

class RedirectConfiguration():
    _attribute_map = {
        "redirect_type": {"key": "redirectType", "type": "str"},
        "include_query_string": {"key": "includeQueryString", "type": "bool"},
        "target_listener_name": {"key": "targetListenerName", "type": "str"},
        "include_path": {"key": "includePath", "type": "bool"},
        "target_url": {"key": "targetUrl", "type": "str"}    
    }

    def __init__(self, redirect_type=None, include_query_string=None, target_listener_name=None, include_path=None, target_url=None, **kwargs):
         super(RedirectConfiguration, self).__init__(**kwargs)

    def transform(self):

class UrlPathMap(): 
    _attribute_map = {
        "default_backend_address_pool_name": {"key": "defaultBackendAddressPoolName", "type": "str"},
        "default_backend_http_settings_name": {"key": "defaultBackendHttpSettingsName", "type": "str"},
        "default_redirect_configuration_name": {"key": "defaultRedirectConfigurationName", "type": "str"},
        "path_rules": {"key": "pathRules", "type": "[PathRule]"}
    }

    def __init__(self, default_backend_address_pool_name=None, default_backend_http_settings_name=None, default_redirect_configuration_name=None, path_rules=None, **kwargs):
        super(UrlPathMap, self).__init__(**kwargs)

    def transform(self):

class PathRule():
    _attribute_map = {
        "paths": {"key": "paths", "type": "[str]"},
        "backend_address_pool_name": {"key": "backendAddressPoolName", "type": "str"},
        "backend_http_settings_name": {"key": "backendHttpSettingsName", "type": "str"},
        "redirect_configuration_name": {"key": "redirectConfigurationName", "type": "str"}
    }

    def __init__(self, paths=None, backend_address_pool_name=None, backend_http_settings_name=None, redirect_configuration_name=None, **kwargs):
        super(PathRule, self).__init__(**kwargs)

    def transform(self):

class RequestRoutingRule():
    _attribute_map = {
        "http_listener_name": {"key": "httpListenerName", "type": "str"},
        "rule_type": {"key": "ruleType", "type": "str"},
        "backend_address_pool_name": {"key": "backendAddressPoolName", "type": "str"},
        "backend_http_settings_name": {"key": "backendHttpSettingsName", "type": "str"},
        "redirect_configuration_name": {"key": "redirectConfigurationName", "type": "str"},
        "url_path_map_name": {"key": "urlPathMapName", "type", "str"}
    }

    def __init__(self, http_listener_name=None, rule_type=None, backend_address_pool_name=None, backend_http_settings_name=None, redirect_configuration_name=None, url_path_map_name=None, **kwargs):
        super(RequestRoutingRule, self).__init__(**kwargs)

    def transform(self):

class WebApplicationFirewallConfiguration():
    _attribute_map = {
        "enabled": {"key": "enabled", "type": "bool"},
        "firewall_mode": {"key": "firewallMode", "type": "str"},
        "rule_set_type": {"key": "ruleSetType", "type": "str"},
        "rule_set_version": {"key": "ruleSetVersion", "type": "str"},
        "disabled_rule_groups": {"key": "disabledRuleGroups", "type": "[DisabledRuleGroup]"}
    }

    def __init__(self, enabled=None, firewall_mode=None, rule_set_type=None, rule_set_version=None, disabled_rule_groups=None, **kwargs):
        super(WebApplicationFirewallConfiguration, self).__init__(**kwargs)

    def transform(self):

class DisabledRuleGroup():
    _attribute_map = {
        "rule_group_name": {"key": "ruleGroupName", "type": "str"},
        "rules": {"key": "rules", "type": "[str]"}
    }

    def __init__(self, rule_group_name=None, rules=None, **kwargs):
        super(DisabledRuleGroup, self).__init__(**kwargs)

    def transform(self):
        
class Probe():
    _attribute_map = {
        "protocol": {"key": "protocol", "type": "str"},
        "host": {"key": "host",, "type": "str"},
        "path": {"key": "path", "type": "str"},
        "interval": {"key": "interval", "type": "int"},
        "timeout": {"key": "timeout", "type": "int"},
        "unhealthy_threshold": {"key": "unhealthyThreshold", "type": "int"},
        "pick_host_name_from_backend_http_settings": {"key": "pickHostNameFromBackendHttpSettings", "type": "bool"},
        "min_servers": {"key": "minServers", "type": "int"},
        "match": {"key": "match", "type": "Match"}
    }

    def __init__(self, protocol=None, host=None, path=None, interval=None, timeout=None, unhealthy_threshold=None, pick_host_name_from_backend_http_settings=None, min_servers=None, match=None, **kwargs):
        super(Probe, self).__init__(**kwargs)

    def transform(self):

class Match():
    _attribute_map = {
        "body": {"key": "body", "type": "str"},
        "status_codes": {"key": "statusCodes", "type": "[str]"}
    }

    def __init__(self, body=None, status_codes=None, **kwargs):
        super(Match, self).__init__(**kwargs)

    def transform(self):

class SslCertificate():
    _attribute_map = {
        "data": {"key": "data", "type": "str"},
        "password": {"key": "password", "type": "str"}
    }

    def __init__(self, data=None, password=None, **kwargs):
        super(SslCertificate, self).__init__(**kwargs)

    def transform(self):

class AuthenticationCertificate():
    _attribute_map = {
        "data": {"key": "data", "type": "str"}
    }

    def __init__(self, data=None, **kwargs):
        super(AuthenticationCertificate, self).__init__(**kwargs)

    def transform(self):

class FrontEndPorts():
    _attribute_map = {
        "port": {"key": "port", "type": "int"}
    }

    def __init__(self, port=None, **kwargs):
        super(FrontEndPorts, self).__init__(**kwargs)

    def transform(self):

class SslPolicy():
    _attribute_map = {
        "policy_type": {"key": "policyType", "type": "str"},
        "policy_name": {"key": "policyName", "type": "str"},
        "disabled_ssl_protocols": {"key": "disabledSslProtocols", "type": "[str]"},
        "chipher_suites": {"key": "cipherSuites", "type": "[str]"},
        "min_protocol_version": {"key": "minProtocolVersion", "type", "[str]"}
    }

    def __init__(self, policy_type=None, policy_name=None, disabled_ssl_protocols=None, chiper_suites=None, min_protocol_version=None, **kwargs):
        super(SslPolicy, self).__init__(**kwargs)

    def transform(self):

