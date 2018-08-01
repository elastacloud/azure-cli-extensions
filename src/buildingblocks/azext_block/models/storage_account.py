# https://github.com/mspnp/template-building-blocks/tree/andrew/storage-spike/extensions
from azure.mgmt.storage.models import (StorageAccountCreateParameters as StorageAccountCreateParametersSdk,
    SkuName,
    SkuTier,
    Kind)

from msrestazure.tools import resource_id

from .building_block_settings import (BuildingBlock,
                                      RegisterBuildingBlock)
from .resources import (Resource,
                        ResourceId,
                        TaggedResource,
                        TopLevelResource,
                        ResourceReference,
                        BuildingBlockModel,
                        convert_string_to_enum,
                        extract_resource_groups)

@RegisterBuildingBlock(name='Storage', template_url='resources/Microsoft.Storage/storageAccounts.json', deployment_name='st')
class StorageAccountBuildingBlock(BuildingBlock):
    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[StorageAccount]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(StorageAccountBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    @classmethod
    def onregister(self):
        self.register_sdk_model(StorageAccountCreateParametersSdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}
        })

    def transform(self):
        storage_accounts = [storage_account.transform() for storage_account in self.settings]

        resource_groups = extract_resource_groups(storage_accounts)
        template_parameters = {
            "storageAccounts": storage_accounts
        }

        return resource_groups, template_parameters

@ResourceId(namespace='Microsoft.Storage', type='storageAccounts')
class StorageAccount(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        'sku': {'key': 'sku', 'type': 'str'},
        'supports_https_traffic_only': {'key': 'supportsHttpsTrafficOnly', 'type': 'bool'},
        'encrypt_blob_storage': {'key': 'encryptBlobStorage', 'type': 'bool'},
        'encrypt_file_storage': {'key': 'encryptFileStorage', 'type': 'bool'},
        'encrypt_queue_storage': {'key': 'encryptQueueStorage', 'type': 'bool'},
        'encrypt_table_storage': {'key': 'encryptTableStorage', 'type': 'bool'},
        'key_vault_properties': {'key': 'keyVaultProperties', 'type': 'string'},
        'tables': {'key': 'tables', 'type': '[str]'},
        'queues': {'key': 'queues', 'type': '[str]'},
        'containers': {'key': 'containers', 'type': '[str]'},
        'shares': {'key': 'shares', 'type': '[str]'}
    }

    def __init__(self, sku=None, supports_https_traffic_only=None, encrypt_blob_storage=None, encrypt_file_storage=None, encrypt_queue_storage=None, encrypt_table_storage=None, key_vault_properties=None, tables=None, queues=None, containers=None, shares=None, **kwargs):
        super(StorageAccount, self).__init__(**kwargs)
        self.sku = sku if sku else 'Standard_LRS'
        self.supports_https_traffic_only = supports_https_traffic_only if supports_https_traffic_only else True
        self.encrypt_blob_storage = encrypt_blob_storage if encrypt_blob_storage else False
        self.encrypt_file_storage = encrypt_file_storage if encrypt_file_storage else False
        self.encrypt_queue_storage = encrypt_queue_storage if encrypt_queue_storage else False
        self.encrypt_table_storage = encrypt_blob_storage if encrypt_table_storage else False
        self.key_vault_properties = key_vault_properties if key_vault_properties else None
        self.tables = tables if tables else []
        self.queues = queues if queues else []
        self.containers = containers if containers else []
        self.shares = shares if shares else []
        self._validation.update({

        })
        
    def transform(self):
        factory = StorageAccountBuildingBlock.get_sdk_model(StorageAccountCreateParametersSdk)

        model = factory(
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            location=self.location,
            tags=self.tags,
            name=self.name,
            sku=self.sku,
            kind='Storage',
            enable_https_traffic_only=self.supports_https_traffic_only
        )

        return model  