from msrestazure.tools import resource_id

from azure.mgmt.network.models import (NetworkInterface as NetworkInterfaceSdk, 
                                        NetworkInterfaceIPConfiguration as NetworkInterfaceIPConfigurationSdk, 
                                        Subnet as SubnetSdk,
                                        NetworkInterfaceDnsSettings as NetworkInterfaceDnsSettingsSdk,
                                        SubResource)
from .building_block_settings import (BuildingBlock, RegisterBuildingBlock)
from .resources import (Resource,
                        ResourceId,
                        TaggedResource,
                        TopLevelResource,
                        convert_string_to_enum,
                        extract_resource_groups)
from ..validations import (ValidationFunction)
from .public_ip_address import (PublicIPAddress)

BuildingBlock.register_sdk_model(NetworkInterfaceSdk, {
    'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
    'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}
})

@ResourceId(namespace="Microsoft.Network", type="NetworkInterface")
class NetworkInterface(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        'is_public': {'key': 'isPublic', 'type': 'str'},
        'subnet_name': {'key': 'subnetName', 'type': 'str'},
        'private_ip_allocation_method': {'key': 'privateIPAllocationMethod', 'type': 'str'},
        'private_ip_address_version': {'key': 'privateIPAddressVersion', 'type':'str'},
        'public_ip_allocation_method': {'key': 'publicIPAllocationMethod', 'type':'str'},
        'starting_ip_address': {'key': 'starting_IP_Address', 'type': 'str'},
        'enable_ip_forwarding': {'key': 'enable_ip_forwarding', 'type': 'str'},
        'dns_servers': {'key': 'dnsServers', 'type': 'str'},
        'is_primary': {'key': 'isPrimary', 'type': 'str'},
        'domain_name_label_prefix': {'key': 'domainNameLabelPrefix', 'type':'str'},
        'backend_pool_names': {'key': 'backendPoolNames', 'type': 'str'},
        'inbound_nat_rules_names': {'key': 'inboundNATRulesNames', 'type': 'str'}
    }

    def __init__(self, is_public=None, subnet_name=None,private_ip_allocation_method=None,private_ip_address_version=None,
        public_ip_allocation_method=None,starting_ip_address=None,enable_ip_forwarding=None,dns_servers=None,is_primary=None, 
        domain_name_label_prefix=None,backend_pool_names=None,inbound_nat_rules_names=None , **kwargs):
        super(NetworkInterface, self).__init__(**kwargs)
        self.is_public = is_public if is_public else True,
        self.subnet_name = subnet_name,
        self.private_ip_allocation_method = private_ip_allocation_method if private_ip_allocation_method else 'Dynamic',
        self.private_ip_address_version = private_ip_address_version if private_ip_address_version else 'IPv4',
        self.public_ip_allocation_method = public_ip_allocation_method if public_ip_allocation_method else 'Dynamic',
        self.starting_ip_address = starting_ip_address,
        self.enable_ip_forwarding = enable_ip_forwarding,
        self.dns_servers = dns_servers,
        self.is_primary = is_primary,
        self.domain_name_label_prefix = domain_name_label_prefix,
        self.backend_pool_names = backend_pool_names,
        self.inbound_nat_rules_names = inbound_nat_rules_names

        self._validation.update({
            'is_public': {'required': True},
            'subnet_name': {'required': True}
         })

    def transform(self):
        factory = BuildingBlock.get_sdk_model(NetworkInterfaceSdk)

        model = factory(
            id=self.id, # pylint: disable=no-member
            name=self.name,
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            location=self.location,
            tags=self.tags,
            ip_configurations = self.ipConfigurationsTransform(private_ip_allocation_method = self.private_ip_allocation_method, private_ip_address_version = self.private_ip_address_version, 
                public_ip_allocation_method = self.public_ip_allocation_method, subnet_name = self.subnet_name, virtual_network_name = self.name),
            enable_ip_forwarding= self.enable_ip_forwarding,
            dns_settings = self.dnsSettingsTransform(self.dns_servers),
            primary = self.is_primary
        )

        return model

    def dnsSettingsTransform(self, dns_servers=None):

        factory = BuildingBlock.get_sdk_model(NetworkInterfaceDnsSettingsSdk)

        model = factory(
            applied_dns_servers = self.dns_servers,
            dns_servers = self.dns_servers
        )

        return model

    def ipConfigurationsTransform(self, virtual_network_name=None, is_public=None, private_ip_allocation_method=None, private_ip_address_version=None, public_ip_allocation_method=None, subnet_name=None, starting_ip_address=None):
        factory = BuildingBlock.get_sdk_model(NetworkInterfaceIPConfigurationSdk)

        if self.is_public:
            self.public_ip_address = SubResource(id=resource_id(
                subscription=self.subscription_id,
                resource_group=self.resource_group_name,
                namespace='Microsoft.Network',
                type='publicIPAddresses',
                name="{}-pip".format(virtual_network_name)))

        model = factory(
            private_ip_allocation_method = self.private_ip_allocation_method,
            private_ip_address_version = self.private_ip_address_version,
            subnet = SubResource(id=resource_id(
            subscription=self.subscription_id,
            resource_group=self.resource_group_name,
            namespace='Microsoft.Network',
            type='virtualNetworks',
            name=virtual_network_name,
            child_type_1="subnets",
            child_name_1=self.subnet_name,
            )),
            public_ip_address = self.public_ip_address,
            private_ip_address = self.starting_ip_address if private_ip_allocation_method == 'static' else None
        )

        return model
    







