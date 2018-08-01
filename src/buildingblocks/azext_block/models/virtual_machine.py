# TODO: Create default auto scale setting profiles
# Scale sets
# Finish storage
# Key Vault


# Questions UsePlan - What is it?


# Virtual machine model imports
from azure.mgmt.compute.models import (VirtualMachine as VirtualMachineSdk, 
    AvailabilitySet as AvailabilitySetSdk, 
    VirtualMachineScaleSet as VirtualMachineScaleSetSdk,
    VirtualMachineScaleSetSkuScaleType,
    OSDisk as OSDiskSdk,
    ImageReference as ImageReferenceSdk,
    DataDisk as DataDiskSdk,
    VirtualMachineSizeTypes,
    OperatingSystemTypes,
    HardwareProfile as HardwareProfileSdk,
    OSProfile as OSProfileSdk,
    Plan as PlanSdk,
    WindowsConfiguration as WindowsConfigurationSdk,
    StorageProfile as StorageProfileSdk,
    ManagedDiskParameters as ManagedDiskParametersSdk)

# Autoscale settings
from azure.mgmt.monitor.models import (
    AutoscaleProfile as AutoScaleProfileSdk,
    ScaleCapacity as ScaleCapacitySdk,
    ScaleRule as ScaleRuleSdk,
    MetricTrigger as MetricTriggerSdk,
    ScaleAction as ScaleActionSdk
)

# Local model imports
from .application_gateway import (ApplicationGateway)
from .load_balancer import (LoadBalancer)
# Building block imports
from .building_block_settings import (BuildingBlock, RegisterBuildingBlock)
# Resource imports
from .resources import (Resource, ResourceId, ResourceReference, TaggedResource, TopLevelResource, extract_resource_groups)
# Validation imports
from ..validations.networking import (is_valid_cidr)
from ..validations.virtual_machine import (is_valid_os_type)
from ..validations import ValidationFunction
from enum import Enum
from .public_ip_address import (PublicIPAddress)
from .network_interface import (NetworkInterface)

# Register building block
@RegisterBuildingBlock(name='VirtualMachine', template_url='buildingBlocks/virtualMachines/virtualMachines.json', deployment_name='vm')
class VirtualMachineBuildingBlock(BuildingBlock):
    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[VirtualMachine]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(VirtualMachineBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    def transform(self):
        secret = []
        auth = Authentication('M!crs0ft123')
        secret.append(Secret(auth))

        secrets = Secrets(secret)

        i = 1
        for virtual_machine in self.settings:
            virtual_machine.name = '{}-vm{}'.format(virtual_machine.name_prefix, str(i))
            i += 1

        virtual_machines = [vm.transform() for vm in self.settings]

        network_interfaces = [nic.transform() for virtual_machine in self.settings for nic in virtual_machine.nics]

        vms = VM(virtual_machines = virtual_machines, network_interfaces = network_interfaces)
        #availability_set = [availability_set.transform() for availability_set in virtual_machines.availability_set]
        #application_gateways = [application_gateway.transform() for application_gateway in virtual_machines.application_gateway_settings]

        #public_ip_addresses = self.get_ip_addresses(self.settings.nics)

        resource_groups = extract_resource_groups(virtual_machines)
        template_parameters = {
            "virtualMachines": vms,
            "secrets": secrets
        }
        #"publicIpAddresses": public_ip_addresses,
        #"networkInterfaces": network_interfaces,
        #"storageAccounts": storage_accounts,
        #"diagnosticStorageAccounts": diagnostic_storage_accounts,
        #"availabilitySet": availability_set,
        #"loadBalancers": load_balancers,
        #"scaleSets": scale_sets,
        #"autoScaleSettings": auto_scale_settings,
        #"applicationGateways": application_gateways,
        return resource_groups, template_parameters

    def get_ip_addresses(self,network_interfaces):
        public_ip_addresses = []

        '''
        nics = [nic for nic in network_interfaces if network_interface.is_public == True]
        for nic in nics:
            public_ip_address_parameters = {
                'subscription_id': self.subscription_id,
                'resource_group_name': self.resource_group_name,
                'location': self.location,
                'name': "{}-{}-pip".format(nic.virtual_machine.name,  nic.name),
                'public_ip_allocation_method': 'Dynamic',
                'public_ip_address_version': "IPv4",
                'idle_timeout_in_minutes': None,
                'zones': None,
                'domain_name_label': None
            }

            public_ip_address = PublicIPAddress(**public_ip_address_parameters)
            public_ip_addresses.append(public_ip_address.transform())
        '''
        return public_ip_addresses

    @classmethod
    def onregister(cls):
        cls.register_sdk_model(VirtualMachineSdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}#
        })

class VM():
    _attribute_map = {
        'publicIpAddresses': {'key': 'publicIpAddresses', 'type': '[str]'},
        'networkInterfaces': {'key': 'networkInterfaces', 'type': '[NetworkInterface]'},
        'storageAccounts': {'key': 'storageAccounts', 'type': '[str]'},
        'diagnosticStorageAccounts': {'key': 'diagnosticStorageAccounts', 'type': '[str]'},
        'availabilitySet': {'key': 'availabilitySet', 'type': '[str]'},
        'loadBalancers': {'key': 'loadBalancers', 'type': '[str]'},
        'scaleSets': {'key': 'scaleSets', 'type': '[str]'},
        'autoScaleSettings': {'key': 'autoScaleSettings', 'type': '[str]'},
        'applicationGateways': {'key': 'applicationGateways', 'type':'[str]'},
        'virtualMachines': {'key': 'virtualMachines', 'type': '[VirtualMachine]'}
    }

    def __init__(self, public_ip_addresses = None, network_interfaces = None, storage_accounts = None, diagnostic_storage_accounts = None, availability_set = None, load_balancers = None, scale_sets = None, auto_scale_settings = None, application_gateways = None, virtual_machines = None, **kwargs):
        self.public_ip_addresses = public_ip_addresses if public_ip_addresses else []
        self.network_interfaces = network_interfaces if network_interfaces else []
        self.storage_accounts = storage_accounts if storage_accounts else []
        self.diagnostic_storage_accounts = diagnostic_storage_accounts if diagnostic_storage_accounts else []
        self.availability_set = self.availability_set if availability_set else []
        self.load_balancers = load_balancers if load_balancers else []
        self.scale_sets = scale_sets if scale_sets else []
        self.auto_scale_settings = auto_scale_settings if auto_scale_settings else []
        self.application_gateways = application_gateways if application_gateways else []
        self.virtual_machines = virtual_machines if virtual_machines else []
        

@ResourceId(namespace="Microsoft.Compute", type="virtualMachines")
class VirtualMachine(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        'vm_count': {'key': 'vmCount', 'type': 'int'},
        'name_prefix': {'key': 'namePrefix', 'type':'str'},
        'computer_name_prefix': {'key': 'computerNamePrefix', 'type': 'str'},
        'size': {'key': 'size', 'type':'str'},
        'os_type':{'key': 'osType', 'type':'str'},
        'image_reference': {'key': 'imageReference', 'type': 'ImageReference'},
        'admin_username': {'key': 'adminUsername', 'type': 'str'},
        'admin_password': {'key': 'adminPassword', 'type': 'str'},
        'ssh_public_key': {'key': 'sshPublicKey', 'type': 'str'},
        'nics': {'key': 'nics', 'type': '[NetworkInterface]', 'parent': 'virtual_machine'},
        'os_disk': {'key': 'osDisk', 'type': 'OSDisk'},
        'data_disk': {'key': 'dataDisk', 'type':'DataDisk'},
        'availability_set': {'key': 'availabilitySet', 'type': 'AvailabilitySet'},
        'diagnostic_storage_accounts': {'key': 'diagnosticStorageAccounts', 'type': '[DiagnosticStorageAccount]'},
        'storage_accounts': {'key': 'storageAccounts','type': '[StorageAccount]'},
        'scale_set_settings': {'key': 'scaleSetSettings', 'type':'ScaleSetSettings', 'parent': 'virtual_machine'},
        'load_balancer_settings': {'key': 'loadBalancerSettings', 'type': 'LoadBalancer'},
        'application_gateway_settings': {'key': 'applicationGatewaySettings','type': 'ApplicationGateway'},
        'existing_windows_server_license': {'key': 'existingWindowsServerlicense', 'type': 'str'}
    }

    _valid_os_types = frozenset([e.value for e in OperatingSystemTypes])
    _valid_sizes = frozenset([e.value for e in VirtualMachineSizeTypes])

    def __init__(self, vm_count=None, name_prefix=None, computer_name_prefix=None,size=None,os_type=None,image_reference=None,admin_username=None,admin_password=None,ssh_public_key=None, nics=None,os_disc=None,data_disks=None,availability_sets=None,diagnostic_storage_accounts=None,storage_accounts=None,scale_set_settings=None,load_balancer_settings=None,application_gateway_settings=None, existing_windows_server_license=None, **kwargs):
        super(VirtualMachine, self).__init__(**kwargs)
        self.vm_count = vm_count if vm_count else 1
        self.name_prefix = name_prefix
        self.computer_name_prefix = computer_name_prefix
        self.size = size if size else 'Standard_DS2_v2'
        self.os_type = os_type if os_type else None
        self.image_reference = image_reference if image_reference else None
        self.admin_username = admin_username if admin_username else None
        self.admin_password = admin_password if admin_password else None
        self.ssh_public_key = ssh_public_key if ssh_public_key else None
        self.nics = nics if nics else None
        self.os_disc = os_disc if os_disc else None
        self.data_disks = data_disks if data_disks else None
        self.availability_sets = availability_sets if availability_sets else None
        self.diagnostic_storage_accounts = diagnostic_storage_accounts if diagnostic_storage_accounts else None
        self.storage_accounts = storage_accounts if storage_accounts else None
        self.scale_set_settings = scale_set_settings if scale_set_settings else None
        self.load_balancer_settings = load_balancer_settings if load_balancer_settings else None
        self.application_gateway_settings = application_gateway_settings if application_gateway_settings else None
        self.existing_windows_server_license = existing_windows_server_license if existing_windows_server_license else False

        self._validation.update({
            'name_prefix': {'required': True},
            'computer_name_prefix': {'custom': VirtualMachine._is_valid_computer_name_prefix},
            'os_type': {'required': True, 'custom': VirtualMachine.is_valid_os_type},
            'size': {'required': True, 'custom': self.is_valid_size},
            'admin_username': {'required': True, 'custom': VirtualMachine._is_valid_admin_username},
            'admin_password': {'custom': self._is_valid_admin_password},
            'ssh_public_key': {'custom': self._is_valid_ssh_public_key},
            'nics': {'required': True, 'min_items': 1, 'custom': self._is_valid_nic}, # TODO: Validate nic location is same location as VM
            'vm_count': {'custom': VirtualMachine._is_valid_vm_count},
            'image_reference': {'custom': VirtualMachine._is_valid_image_reference},
            'existing_windows_server_license': {'custom': self._is_valid_existing_windows_license},
            'storage_accounts': {'custom': self._is_valid_storage_accounts},
            'diagnostic_storage_accounts': {'custom': self._is_valid_diagnostic_storage_accounts}
        })

    def transform(self):
        image_reference = ImageReferenceSdk(publisher='MicrosoftWindowsServer', offer='WindowsServer', sku='2016-Datacenter', version='latest')
        factory = VirtualMachineBuildingBlock.get_sdk_model(OSDiskSdk)

        os_disk = factory(
            name='{}-os'.format(self.name),
            create_option='fromImage',
            caching='ReadWrite',
            os_type='Windows',
            managed_disk=ManagedDiskParametersSdk(storage_account_type='Premium_LRS')
        )

        storage_profile = StorageProfileSdk(image_reference=image_reference, os_disk=os_disk, data_disks=None)

        factory = VirtualMachineBuildingBlock.get_sdk_model(OSProfileSdk)

        os_profile = factory(
            admin_username=self.admin_username, 
            admin_password='$AUTHENTICATION$', 
            computer_name=self.name, secrets=[], 
            windows_configuration=WindowsConfigurationSdk(provision_vm_agent=True)
        )

        factory = VirtualMachineBuildingBlock.get_sdk_model(VirtualMachineSdk)
        model = factory(
            id=self.id, # pylint: disable=no-member
            name=self.name,
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            location = self.location,
            tags=self.tags,
            hardware_profile = HardwareProfileSdk(vm_size=self.size),
            os_profile = os_profile,
            storage_profile=storage_profile
        )

        return model

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_os_types)))
    def is_valid_os_type(self, value):
        if value in self._valid_os_types:
            return True
        else:
            return False

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_sizes)))
    def is_valid_size(self, value):
        if value in self._valid_sizes:
            return True
        else: 
            return False

    @ValidationFunction()
    def _is_valid_computer_name_prefix(self, value):
        if value == None:
            if self.name_prefix != None:
                if len(value + '000000') > 15:
                    return False, 'Computer name length cannot be greater than 15. If computerNamePrefix value is not specified, then computer name is computed using namePrefix: ' + self.name_prefix + '000000'
                else:
                    return True
            elif self.name_prefix == None:
                return False, 'If computerNamePrefix is not specified, then .namePrefix must be provided'
        elif len(value + '000000') > 15:
            return False, 'Computer name length cannot be greater than 15. Computer name is computed using computerNamePrefix: ' + value + '000000'
        else:
            return True

    @ValidationFunction('Value must be greater than 0')
    def _is_valid_vm_count(self, value):
        if value > 0:
            return True
        else:
            return False

    @ValidationFunction()
    def _is_valid_image_reference(self, value):
        pass # line 353

    @ValidationFunction()
    def _is_valid_existing_windows_license(self, value):
        pass # line 811

    @ValidationFunction()
    def _is_valid_admin_username(self, value):
        invalidCharacters = {'[', ']', ':', '|', '<', '>', '+', '=', ';', ',', '?', '*', '@'}

        if len(value) > 20 or value.endswith('.'):
            return False, 'adminUsername cannot be more than 20 characters long or end with a period(.)'
        elif any(character in value for character in invalidCharacters):
            return False, 'adminUsername cannot contains these characters: " [ ] : | < > + = ; , ? * @'
        else:
            return True

    @ValidationFunction()
    def _is_valid_admin_password(self, value):
        pass # line 841

    @ValidationFunction()
    def _is_valid_ssh_public_key(self, value):
        pass #line 875

    @ValidationFunction()
    def _is_valid_storage_accounts(self, value):
        pass # line 897

    @ValidationFunction()
    def _is_valid_diagnostic_storage_accounts(self, value):
        pass # line 900

    @ValidationFunction()
    def _is_valid_nic(self, value):
        pass # line 1015

    @ValidationFunction()
    def _is_valid_scalability_set(self, value):
        pass # line 1030

    @ValidationFunction()
    def _is_valid_load_balancer(self, value):
        pass # 1049

    @ValidationFunction()
    def _is_valid_application_gateway(self, value):
        pass # line 1075

    @ValidationFunction()
    def _is_valid_scaleset(self, value):
        pass # line 1096

    @ValidationFunction()
    def _is_valid_extension(self, value):
        pass # line 1123

    @ValidationFunction()
    def _is_valid_secret(self, value):
        pass # line 1140 

class ImageReference(Resource):
    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'publisher': {'key': 'publisher', 'type': 'str'},
        'offer': {'key': 'offer', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'}
    }

    def __init__(self, id=None, publisher=None, offer=None, sku=None, version=None, **kwargs):
        super(ImageReference, self).__init__(**kwargs)
        self.id = id if id else None
        self.publisher = publisher if publisher else None
        self.offer = offer if offer else None
        self.sku = sku if sku else None
        self.version = version if version else 'latest'
        self._validation.update({
            'id': {'required': True},
            'publisher': {'required': True},
            'offer': {'required': True},
            'sku': {'required': True},
            'version': {'required': True}
        })

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(ImageReferenceSdk)
        model = factory(
            id = self.id,
            publisher = self.publisher,
            offer = self.offer,
            sku = self.sku,
            version = self.version
        )

        return model

class OSDisk(Resource):
    _attribute_map = {
        'create_option': {'key': 'createOption', 'type': 'str'},
        'caching': {'key': 'caching', 'type': 'str'},
        'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
        'images': {'key': 'images', 'type': '[str]'}
    }

    def __init__(self, create_option=None,caching=None,disk_size_gb=None,images=None, **kwargs):
        super(OSDisk, self).__init__(**kwargs)
        self._validation.update({
            'images': {'required': True, 'min_items': 1}
        })

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(OSDiskSdk)
        model = factory(
            name = self.name
        )

        return model

class DataDisk(Resource):
    _attribute_map = {
         'count': {'key': 'count', 'type': 'int'},
         'caching': {'key': 'caching', 'type': 'str'},
         'create_option': {'key': 'createOption', 'type': 'str'},
         'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
         'disks': {'key': 'disks', 'type': '[Disk]'}
    }

    def __init__(self, count=None, caching=None, create_option=None, disk_size_gb=None, disks=None, **kwargs):
        super(DataDisk, self).__init__(**kwargs)
        self._validation.update({})

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(DataDiskSdk)
        model = factory(
            name = self.name
        )

        return model

class AvailabilitySet(Resource):
    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'platform_fault_domain_count': {'key': 'platformFaultDomainCount', 'type': 'int'},
        'platform_update_domain_count': {'key': 'platformUpdateDomainCount', 'type': 'int'}
    }

    def __init__(self, name=None,platform_fault_domain_count=None, platform_update_domain_count=None, **kwargs):
        super(AvailabilitySet, self).__init__(**kwargs)
        self.platform_fault_domain_count = platform_fault_domain_count if platform_fault_domain_count else 3
        self.platform_update_domain_count = platform_update_domain_count if platform_update_domain_count else 5
        self._validation.update({
            'name': {'required': True},
            'platform_fault_domain_count': {'required': False, 'custom': AvailabilitySet._is_valid_platform_fault_domain_count},
            'platform_update_domain_count': {'required': False, 'custom': AvailabilitySet.is_valid_platform_update_domain_count}
        })

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(AvailabilitySetSdk)
        model = factory(
            name = self.name,
            platform_fault_domain_count = self.platform_fault_domain_count,
            platform_update_domain_count = self.platform_update_domain_count
        )

        return model

    @classmethod
    @ValidationFunction('Value must be between 1 and 3')
    def _is_valid_platform_fault_domain_count(self, value):
        if value >= 1 and value <= 3:
            return True
        else:
            return False

    @classmethod
    @ValidationFunction('Value must be between 1 and 20')
    def is_valid_platform_update_domain_count(self, value):
        if value >= 1 and value <= 20:
            return True
        else:
            return False 

class DiagnosticStorageAccount(Resource):
    _attribute_map = {
        'count': {'key': 'count', 'type': 'int'},
        'name_suffix': {'key': 'nameSuffix', 'type': 'str'},
        'sku_type': {'key': 'skuType', 'type': 'str'},
        'supports_https_traffic_only':{'key': 'supportsHttpsTrafficOnly', 'type': 'bool'},
        'encrypt_blob_storage': {'key': 'encryptBlobStorage', 'type': 'bool'},
        'encrypt_file_storage': {'key': 'encryptFileStorage', 'type': 'bool'},
        'key_vault_properties': {'key': 'keyVaultProperties', 'type': 'KeyVaultProperties'},
        'accounts': {'key': 'accounts', 'type': '[str]'}
    }

    def __init__(self, count=None, name_suffix=None, sku_type=None, supports_https_traffic_only=None, encrypt_blob_storage=None, encrypt_file_storage=None, key_vault_properties=None, accounts=None, **kwargs):
        super(DiagnosticStorageAccount, self).__init__(**kwargs)
        self._validation.update({})

    def transform(self):
        pass
        
class StorageAccount(Resource):
    _attribute_map = {
        'count': {'key': 'count', 'type': 'int'},
        'managed': {'key': 'managed', 'type': 'bool'},
        'name_suffix': {'key': 'nameSuffix', 'type': 'str'},
        'sku_type': {'key': 'skuType', 'type': 'str'},
        'supports_https_traffic_only':{'key': 'supportsHttpsTrafficOnly', 'type': 'bool'},
        'encrypt_blob_storage': {'key': 'encryptBlobStorage', 'type': 'bool'},
        'encrypt_file_storage': {'key': 'encryptFileStorage', 'type': 'bool'},
        'key_vault_properties': {'key': 'keyVaultProperties', 'type': 'KeyVaultProperties'},
        'accounts': {'key': 'accounts', 'type': '[str]'}
    }

    def __init__(self, count=None, managed=None, name_suffix=None, sku_type=None, supports_https_traffic_only=None, encrypt_blob_storage=None, encrypt_file_storage=None, key_vault_properties=None, accounts=None, **kwargs):
        super(StorageAccount, self).__init__(**kwargs)
        self._validation.update({})

    def transform(self):
        pass

class ScaleSetSettings(Resource):
    _attribute_map = {
        'upgrade_policy': {'key': 'updatedPolicy', 'type': 'str'},
        'overprovision': {'key': 'overprovision', 'type': 'bool'},
        'single_placement_group': {'key': 'singlePlacementGroup', 'type': 'bool'},
        'auto_scale_settings': {'key': 'autoscaleSettings', 'type': '[AutoScaleSetting]'}   
    }

    def __init__(self, upgrade_policy=None, overprovision=None, single_placement_group=None, **kwargs):
        super(ScaleSetSettings, self).__init__(**kwargs)
        self.upgrade_policy = upgrade_policy if upgrade_policy else 'Automatic'
        self.overprovision = overprovision if overprovision else True
        self.single_placement_group = single_placement_group if single_placement_group else True
        self._validation.update({
            'upgrade_policy': {'required': True, 'custom': ScaleSetSettings.is_valid_upgrade_policy},
            'overprovision': {'required': True},
            'single_placement_group': {'required': True}
        })

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(VirtualMachineScaleSetSdk)
        
        model = factory(
            upgrade_policy = self.upgrade_policy,
            overprovision = self.overprovision,
            single_placement_group = self.single_placement_group,
            #sku = # TODO,
            #virtual_machine_profile= #TODO
        )

        return model

    @classmethod
    @ValidationFunction('Value must be set to Automatic or Manual')
    def is_valid_upgrade_policy(self, value):
        if value == "Automatic" or value == "Manual":
            return True
        else:
            return False

class Disk(Resource):
    _attribute_map = {
        'caching': {'key': 'caching', 'type': 'str'},
        'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
        'create_option': {'key': 'createOption', 'type': 'str'},
        'images': {'key': 'images', 'type': '[str]'}
    }

    def __init__(self, caching=None, disk_size_gb=None, create_option=None, images=None, **kwargs):
        super(Disk, self).__init__(**kwargs)
        self._validation.update({
            'caching': {'required': True},
            'disk_size_gb': {'required': True},
            'create_option': {'required': True},
            'images': {'required': True, 'min_items': 1}
        })

    def transform(self):
        pass

# Moving to key_vault.py
class KeyVaultProperties(Resource):
    _attribute_map = {
        'key_name': {'key': 'keyName', 'type': 'str'},
        'key_version': {'key': 'keyVersion', 'type': 'str'},
        'key_vault_uri': {'key': 'keyVaultUri', 'type': 'str'}
    }

    def __init__(self, key_name=None, key_version=None, key_vault_uri=None, **kwargs):
        super(KeyVaultProperties, self).__init__(**kwargs)
        self.key_name = key_name if key_name else None
        self.key_version = key_version if key_version else None
        self.key_vault_uri = key_vault_uri if key_vault_uri else None
        self._validation.update({
            'key_name': {'required': True},
            'key_version': {'required': True}
        })

    def transform(self):
        pass

class AutoScaleSetting(Resource):
    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'profiles': {'key': 'profiles', 'type': '[AutoscaleProfileSdk]'}
    }

    def __init__(self, enabled=None, profiles=None, **kwargs):
        super(AutoScaleSetting, self).__init__(**kwargs)
        self.enabled = enabled if enabled else False
        self.profiles = profiles if profiles else []
        
    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(AutoScaleProfileSdk)

        model = factory(
            enabled = self.enabled,
            profiles = self.profiles
        )

        return model

class Secrets(Resource):
    _attribute_map = {
        'secrets': {'key': 'secrets', 'type': '[Secret]'}
    }

    def __init__(self, secrets=None, **kwargs):
        super(Secrets, self).__init__(**kwargs)
        self.secrets = secrets

class Secret(Resource):
    _attribute_map = {
        'authentication': {'key': 'authentication', 'type': 'Authentication'}
    }

    def __init__(self, authentication=None, **kwargs):
        super(Secret, self).__init__(**kwargs)
        self.authentication = authentication

class Authentication():
    _attribute_map = {
        'value': {'key': 'value', 'type': 'str'}
    }

    def __init__(self, value=None, **kwargs):
        super(Authentication, self).__init__(**kwargs)
        self.value = value
        