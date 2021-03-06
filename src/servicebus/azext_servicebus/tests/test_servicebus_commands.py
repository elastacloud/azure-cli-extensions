# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# AZURE CLI SERVICEBUS - NAMESAPCE TEST DEFINITIONS

import time
from azure.cli.testsdk import (ScenarioTest, ResourceGroupPreparer)
from azext_servicebus.servicebus.models import ProvisioningStateDR


# pylint: disable=line-too-long
# pylint: disable=too-many-lines


class SBNamespaceCURDScenarioTest(ScenarioTest):
    @ResourceGroupPreparer(name_prefix='cli_test_sb_namespace')
    def test_sb_namespace(self, resource_group):
        self.kwargs.update({
            'loc': 'westus2',
            'rg': resource_group,
            'namespacename': self.create_random_name(prefix='sb-nscli', length=20),
            'tags': {'tag1: value1'},
            'sku': 'Standard',
            'tier': 'Standard',
            'authoname': self.create_random_name(prefix='cliAutho', length=20),
            'defaultauthorizationrule': 'RootManageSharedAccessKey',
            'accessrights': 'Send',
            'primary': 'PrimaryKey',
            'secondary': 'SecondaryKey'
        })

        # Check for the NameSpace name Availability

        self.cmd('servicebus namespace exists --name {namespacename}',
                 checks=[self.check('nameAvailable', True)])

        # Create Namespace
        self.cmd('servicebus namespace create --resource-group {rg} --name {namespacename} --location {loc} --tags {tags} --sku-name {sku} --sku-tier {tier}',
                 checks=[self.check('sku.name', self.kwargs['sku'])])

        # Get Created Namespace
        self.cmd('servicebus namespace show --resource-group {rg} --name {namespacename}',
                 checks=[self.check('sku.name', self.kwargs['sku'])])

        # Get Created Namespace list by subscription
        listnamespaceresult = self.cmd('servicebus namespace list').output
        self.assertGreater(len(listnamespaceresult), 0)

        # Get Created Namespace list by ResourceGroup
        listnamespacebyresourcegroupresult = self.cmd('servicebus namespace list --resource-group {rg}').output
        self.assertGreater(len(listnamespacebyresourcegroupresult), 0)

        # Create Authoriazation Rule
        self.cmd('servicebus namespace authorizationrule create --resource-group {rg} --namespace-name {namespacename} --name {authoname} --access-rights {accessrights}',
                 checks=[self.check('name', self.kwargs['authoname'])])

        # Get Authorization Rule
        self.cmd('servicebus namespace authorizationrule show --resource-group {rg} --namespace-name {namespacename} --name {authoname}', checks=[self.check('name', self.kwargs['authoname'])])

        # Get Default Authorization Rule
        self.cmd('servicebus namespace authorizationrule show --resource-group {rg} --namespace-name {namespacename} --name {defaultauthorizationrule}',
                 checks=[self.check('name', self.kwargs['defaultauthorizationrule'])])

        # Get Authorization Rule Listkeys
        self.cmd('servicebus namespace authorizationrule keys list --resource-group {rg} --namespace-name {namespacename} --name {authoname}')

        # Regeneratekeys - Primary
        self.cmd('servicebus namespace authorizationrule keys renew --resource-group {rg} --namespace-name {namespacename} --name {authoname} --key-name {primary}')

        # Regeneratekeys - Secondary
        self.cmd('servicebus namespace authorizationrule keys renew --resource-group {rg} --namespace-name {namespacename} --name {authoname} --key-name {secondary}')

        # Delete AuthorizationRule
        self.cmd('servicebus namespace authorizationrule delete --resource-group {rg} --namespace-name {namespacename} --name {authoname}')

        # Delete Namespace list by ResourceGroup
        self.cmd('servicebus namespace delete --resource-group {rg} --name {namespacename}')

    @ResourceGroupPreparer(name_prefix='cli_test_sb_queue')
    def test_sb_queue(self, resource_group):
        self.kwargs.update({
            'loc': 'westus2',
            'rg': resource_group,
            'namespacename': self.create_random_name(prefix='sb-nscli', length=20),
            'tags': {'tag1: value1', 'tag2: value2'},
            'sku': 'Standard',
            'tier': 'Standard',
            'authoname': self.create_random_name(prefix='cliAutho', length=20),
            'defaultauthorizationrule': 'RootManageSharedAccessKey',
            'accessrights': 'Listen',
            'primary': 'PrimaryKey',
            'secondary': 'SecondaryKey',
            'queuename': self.create_random_name(prefix='sb-queuecli', length=25),
            'queueauthoname': self.create_random_name(prefix='cliQueueAutho', length=25),
            'lockduration': 'PT10M'

        })

        # Create Namespace
        self.cmd('servicebus namespace create --resource-group {rg} --name {namespacename} --location {loc} --tags {tags} --sku-name {sku} --sku-tier {tier}',
                 checks=[self.check('sku.name', self.kwargs['sku'])])

        # Get Created Namespace
        self.cmd('servicebus namespace show --resource-group {rg} --name {namespacename}',
                 checks=[self.check('sku.name', self.kwargs['sku'])])

        # Create Queue
        self.cmd('servicebus queue create --resource-group {rg} --namespace-name {namespacename} --name {queuename} --auto-delete-on-idle {lockduration} ', checks=[self.check('name', self.kwargs['queuename'])])

        # Get Queue
        self.cmd('servicebus queue show --resource-group {rg} --namespace-name {namespacename} --name {queuename}',
                 checks=[self.check('name', self.kwargs['queuename'])])

        # Queue List
        self.cmd('servicebus queue list --resource-group {rg} --namespace-name {namespacename}')

        # Create Authoriazation Rule
        self.cmd('servicebus queue authorizationrule create --resource-group {rg} --namespace-name {namespacename} --queue-name {queuename} --name {authoname} --access-rights {accessrights}',
                 checks=[self.check('name', self.kwargs['authoname'])])

        # Get Create Authorization Rule
        self.cmd('servicebus queue authorizationrule show --resource-group {rg} --namespace-name {namespacename} --queue-name {queuename} --name {authoname}',
                 checks=[self.check('name', self.kwargs['authoname'])])

        # Get Authorization Rule Listkeys
        self.cmd('servicebus queue authorizationrule keys list --resource-group {rg} --namespace-name {namespacename} --queue-name {queuename} --name {authoname}')

        # Regeneratekeys - Primary
        regenrateprimarykeyresult = self.cmd('servicebus queue authorizationrule keys renew --resource-group {rg} --namespace-name {namespacename} --queue-name {queuename} --name {authoname} --key-name {primary}')
        self.assertIsNotNone(regenrateprimarykeyresult)

        # Regeneratekeys - Secondary
        regenratesecondarykeyresult = self.cmd(
            'servicebus queue authorizationrule keys renew --resource-group {rg} --namespace-name {namespacename} --queue-name {queuename} --name {authoname} --key-name {secondary}')
        self.assertIsNotNone(regenratesecondarykeyresult)

        # Delete Queue AuthorizationRule
        self.cmd('servicebus queue authorizationrule delete --resource-group {rg} --namespace-name {namespacename} --queue-name {queuename} --name {authoname}')

        # Delete Queue
        self.cmd('servicebus queue delete --resource-group {rg} --namespace-name {namespacename} --name {queuename}')

        # Delete Namespace
        self.cmd('servicebus namespace delete --resource-group {rg} --name {namespacename}')

    @ResourceGroupPreparer(name_prefix='cli_test_sb_topic')
    def test_sb_topic(self, resource_group):
        self.kwargs.update({
            'loc': 'westus2',
            'rg': resource_group,
            'namespacename': self.create_random_name(prefix='sb-nscli', length=20),
            'tags': {'tag1: value1', 'tag2: value2'},
            'sku': 'Standard',
            'tier': 'Standard',
            'authoname': self.create_random_name(prefix='cliAutho', length=20),
            'defaultauthorizationrule': 'RootManageSharedAccessKey',
            'accessrights': 'Send',
            'primary': 'PrimaryKey',
            'secondary': 'SecondaryKey',
            'topicname': self.create_random_name(prefix='sb-topiccli', length=25),
            'topicauthoname': self.create_random_name(prefix='cliTopicAutho', length=25)
        })

        # Create Namespace
        self.cmd(
            'servicebus namespace create --resource-group {rg} --name {namespacename} --location {loc} --tags {tags} --sku-name {sku} --sku-tier {tier}',
            checks=[self.check('sku.name', self.kwargs['sku'])])

        # Get Created Namespace
        self.cmd('servicebus namespace show --resource-group {rg} --name {namespacename}',
                 checks=[self.check('sku.name', self.kwargs['sku'])])

        # Create Topic
        self.cmd(
            'servicebus topic create --resource-group {rg} --namespace-name {namespacename} --name {topicname}',
            checks=[self.check('name', self.kwargs['topicname'])])

        # Get Topic
        self.cmd(
            'servicebus topic show --resource-group {rg} --namespace-name {namespacename} --name {topicname}',
            checks=[self.check('name', self.kwargs['topicname'])])

        # Topic List
        self.cmd('servicebus topic list --resource-group {rg} --namespace-name {namespacename}')

        # Create Authoriazation Rule
        self.cmd('servicebus topic authorizationrule create --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --name {authoname} --access-rights {accessrights}',
                 checks=[self.check('name', self.kwargs['authoname'])])

        # Get Create Authorization Rule
        self.cmd('servicebus topic authorizationrule show --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --name {authoname}', checks=[self.check('name', self.kwargs['authoname'])])

        # Get Authorization Rule Listkeys
        self.cmd('servicebus topic authorizationrule keys list --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --name {authoname}')

        # Regeneratekeys - Primary
        self.cmd('servicebus topic authorizationrule keys renew --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --name {authoname} --key-name {primary}')

        # Regeneratekeys - Secondary
        self.cmd('servicebus topic authorizationrule keys renew --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --name {authoname} --key-name {secondary}')

        # Delete Topic AuthorizationRule
        self.cmd('servicebus topic authorizationrule delete --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --name {authoname}')

        # Delete Topic
        self.cmd('servicebus topic delete --resource-group {rg} --namespace-name {namespacename} --name {topicname}')

    @ResourceGroupPreparer(name_prefix='cli_test_sb_subscription')
    def test_sb_subscription(self, resource_group):
        self.kwargs.update({
            'loc': 'westus2',
            'rg': resource_group,
            'namespacename': self.create_random_name(prefix='sb-nscli', length=20),
            'tags': {'tag1: value1', 'tag2: value2'},
            'sku': 'Standard',
            'tier': 'Standard',
            'authoname': self.create_random_name(prefix='cliAutho', length=20),
            'defaultauthorizationrule': 'RootManageSharedAccessKey',
            'accessrights': 'Send, Listen',
            'primary': 'PrimaryKey',
            'secondary': 'SecondaryKey',
            'topicname': self.create_random_name(prefix='sb-topiccli', length=25),
            'topicauthoname': self.create_random_name(prefix='cliTopicAutho', length=25),
            'subscriptionname': self.create_random_name(prefix='sb-subscli', length=25)
        })

        # Create Namespace
        self.cmd('servicebus namespace create --resource-group {rg} --name {namespacename} --location {loc} --tags {tags} --sku-name {sku} --sku-tier {tier}',
                 checks=[self.check('sku.name', self.kwargs['sku'])])

        # Get Created Namespace
        self.cmd('servicebus namespace show --resource-group {rg} --name {namespacename}',
                 checks=[self.check('sku.name', self.kwargs['sku'])])

        # Create Topic
        self.cmd('servicebus topic create --resource-group {rg} --namespace-name {namespacename} --name {topicname}',
                 checks=[self.check('name', self.kwargs['topicname'])])

        # Get Topic
        self.cmd('servicebus topic show --resource-group {rg} --namespace-name {namespacename} --name {topicname}',
                 checks=[self.check('name', self.kwargs['topicname'])])

        # Create Subscription
        self.cmd('servicebus subscription create --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --name {subscriptionname}',
                 checks=[self.check('name', self.kwargs['subscriptionname'])])

        # Get Create Subscription
        self.cmd('servicebus subscription show --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --name {subscriptionname}',
                 checks=[self.check('name', self.kwargs['subscriptionname'])])

        # Get list of Subscription+
        self.cmd('servicebus subscription list --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname}')

        # Delete Subscription
        self.cmd('servicebus subscription delete --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --name {subscriptionname}')

        # Delete Topic
        self.cmd('servicebus topic delete --resource-group {rg} --namespace-name {namespacename} --name {topicname}')

        # Delete Namespace
        self.cmd('servicebus namespace delete --resource-group {rg} --name {namespacename}')

    @ResourceGroupPreparer(name_prefix='cli_test_sb_rules')
    def test_sb_rules(self, resource_group):
        self.kwargs.update({
            'loc': 'westus2',
            'rg': resource_group,
            'namespacename': self.create_random_name(prefix='sb-nscli', length=20),
            'tags': {'tag1: value1', 'tag2: value2'},
            'sku': 'Standard',
            'tier': 'Standard',
            'authoname': self.create_random_name(prefix='cliAutho', length=20),
            'defaultauthorizationrule': 'RootManageSharedAccessKey',
            'accessrights': 'Listen',
            'primary': 'PrimaryKey',
            'secondary': 'SecondaryKey',
            'topicname': self.create_random_name(prefix='sb-topiccli', length=25),
            'topicauthoname': self.create_random_name(prefix='cliTopicAutho', length=25),
            'subscriptionname': self.create_random_name(prefix='sb-subscli', length=25),
            'rulename': self.create_random_name(prefix='sb-rulecli', length=25),
            'sqlexpression': 'test=test'
        })

        # Create Namespace
        self.cmd('servicebus namespace create --resource-group {rg} --name {namespacename} --location {loc} --tags {tags} --sku-name {sku} --sku-tier {tier}',
                 checks=[self.check('sku.name', self.kwargs['sku'])])

        # Get Created Namespace
        self.cmd('servicebus namespace show --resource-group {rg} --name {namespacename}',
                 checks=[self.check('sku.name', self.kwargs['sku'])])

        # Create Topic
        self.cmd('servicebus topic create --resource-group {rg} --namespace-name {namespacename} --name {topicname} ',
                 checks=[self.check('name', self.kwargs['topicname'])])

        # Get Topic
        self.cmd('servicebus topic show --resource-group {rg} --namespace-name {namespacename} --name {topicname} ',
                 checks=[self.check('name', self.kwargs['topicname'])])

        # Create Subscription
        self.cmd('servicebus subscription create --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --name {subscriptionname}',
                 checks=[self.check('name', self.kwargs['subscriptionname'])])

        # Get Create Subscription
        self.cmd('servicebus subscription show --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --name {subscriptionname}', checks=[self.check('name', self.kwargs['subscriptionname'])])

        # Create Rules
        self.cmd('servicebus rule create --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --subscription-name {subscriptionname} --name {rulename} --filter-sql-expression {sqlexpression}',
                 checks=[self.check('name', self.kwargs['rulename'])])

        # Get Created Rules
        self.cmd('servicebus rule show --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --subscription-name {subscriptionname} --name {rulename}',
                 checks=[self.check('name', self.kwargs['rulename'])])

        # Get Rules List By Subscription
        self.cmd('servicebus rule list --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --subscription-name {subscriptionname}')

        # Delete create rule
        self.cmd('servicebus rule delete --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --subscription-name {subscriptionname} --name {rulename}')

        # Delete create Subscription
        self.cmd('servicebus subscription delete --resource-group {rg} --namespace-name {namespacename} --topic-name {topicname} --name {subscriptionname}')

        # Delete Topic
        self.cmd('servicebus topic delete --resource-group {rg} --namespace-name {namespacename} --name {topicname}')

        # Delete Namespace
        self.cmd('servicebus namespace delete --resource-group {rg} --name {namespacename}')

    @ResourceGroupPreparer(name_prefix='cli_test_sb_alias')
    def test_sb_alias(self, resource_group):

        self.kwargs.update({
            'loc_south': 'SouthCentralUS',
            'loc_north': 'NorthCentralUS',
            'rg': resource_group,
            'namespacenameprimary': self.create_random_name(prefix='sb-nscli', length=20),
            'namespacenamesecondary': self.create_random_name(prefix='sb-nscli', length=20),
            'tags': {'tag1: value1', 'tag2: value2'},
            'sku': 'Premium',
            'tier': 'Premium',
            'authoname': self.create_random_name(prefix='cliAutho', length=20),
            'defaultauthorizationrule': 'RootManageSharedAccessKey',
            'accessrights': 'Send',
            'primary': 'PrimaryKey',
            'secondary': 'SecondaryKey',
            'aliasname': self.create_random_name(prefix='cliAlias', length=20),
            'alternatename': self.create_random_name(prefix='cliAlter', length=20),
            'id': '',
            'test': ''
        })

        self.cmd('servicebus namespace exists --name {namespacenameprimary}',
                 checks=[self.check('nameAvailable', True)])

        # Create Namespace - Primary
        self.cmd('servicebus namespace create --resource-group {rg} --name {namespacenameprimary} --location {loc_south} --tags {tags} --sku-name {sku} --sku-tier {tier}',
                 checks=[self.check('sku.name', self.kwargs['sku'])])

        # Get Created Namespace - Primary
        self.cmd('servicebus namespace show --resource-group {rg} --name {namespacenameprimary}', checks=[self.check('sku.name', self.kwargs['sku'])])

        # Create Namespace - Secondary
        self.cmd('servicebus namespace create --resource-group {rg} --name {namespacenamesecondary} --location {loc_north} --tags {tags} --sku-name {sku} --sku-tier {tier}',
                 checks=[self.check('sku.name', self.kwargs['sku'])])

        # Get Created Namespace - Secondary
        getnamespace2result = self.cmd('servicebus namespace show --resource-group {rg} --name {namespacenamesecondary}',
                                       checks=[self.check('sku.name', self.kwargs['sku'])]).get_output_in_json()

        # Create Authoriazation Rule
        self.cmd('servicebus namespace authorizationrule create --resource-group {rg} --namespace-name {namespacenameprimary} --name {authoname} --access-rights {accessrights}', checks=[self.check('name', self.kwargs['authoname'])])

        partnernamespaceid = getnamespace2result['id']
        self.kwargs.update({'id': partnernamespaceid})
        # Get Create Authorization Rule
        self.cmd('servicebus namespace authorizationrule show --resource-group {rg} --namespace-name {namespacenameprimary} --name {authoname}', checks=[self.check('name', self.kwargs['authoname'])])

        # CheckNameAvailability - Alias

        self.cmd('servicebus georecovery-alias exists --resource-group {rg} --namespace-name {namespacenameprimary} --name {aliasname}', checks=[self.check('nameAvailable', True)])

        # Create alias
        self.cmd('servicebus georecovery-alias create  --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname} --partner-namespace {id}')

        # get alias - Primary
        self.cmd('servicebus georecovery-alias show  --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname}')

        # get alias - Secondary
        self.cmd('servicebus georecovery-alias show  --resource-group {rg} --namespace-name {namespacenamesecondary} --alias {aliasname}')

        getaliasprimarynamespace = self.cmd('servicebus georecovery-alias show  --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname}').get_output_in_json()

        # check for the Alias Provisioning succeeded
        while getaliasprimarynamespace['provisioningState'] != ProvisioningStateDR.succeeded.value:
            time.sleep(30)
            getaliasprimarynamespace = self.cmd('servicebus georecovery-alias show  --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname}').get_output_in_json()

        # Get Authorization Rule
        self.cmd('servicebus georecovery-alias authorizationrule show --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname} --name {authoname}', checks=[self.check('name', self.kwargs['authoname'])])

        # Get AuthorizationRule Keys
        self.cmd('servicebus georecovery-alias authorizationrule keys list --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname} --name {authoname}')

        # Get available AuthorizationRules
        self.cmd('servicebus georecovery-alias authorizationrule list --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname}')

        # Break Pairing
        self.cmd('servicebus georecovery-alias break-pair  --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname}')

        getaliasafterbreak = self.cmd('servicebus georecovery-alias show  --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname}').get_output_in_json()

        # check for the Alias Provisioning succeeded
        while getaliasafterbreak['provisioningState'] != ProvisioningStateDR.succeeded.value:
            time.sleep(30)
            getaliasafterbreak = self.cmd('servicebus georecovery-alias show  --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname}').get_output_in_json()

        # Create alias
        self.cmd('servicebus georecovery-alias create  --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname} --partner-namespace {id}')

        getaliasaftercreate = self.cmd(
            'servicebus georecovery-alias show  --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname}').get_output_in_json()

        # check for the Alias Provisioning succeeded
        while getaliasaftercreate['provisioningState'] != ProvisioningStateDR.succeeded.value:
            time.sleep(30)
            getaliasaftercreate = self.cmd('servicebus georecovery-alias show  --resource-group {rg} --namespace-name {namespacenameprimary} --alias {aliasname}').get_output_in_json()

        # FailOver
        self.cmd('servicebus georecovery-alias fail-over  --resource-group {rg} --namespace-name {namespacenamesecondary} --alias {aliasname}')

        getaliasafterfail = self.cmd(
            'servicebus georecovery-alias show  --resource-group {rg} --namespace-name {namespacenamesecondary} --alias {aliasname}').get_output_in_json()

        # check for the Alias Provisioning succeeded
        while getaliasafterfail['provisioningState'] != ProvisioningStateDR.succeeded.value:
            time.sleep(30)
            getaliasafterfail = self.cmd('servicebus georecovery-alias show  --resource-group {rg} --namespace-name {namespacenamesecondary} --alias {aliasname}').get_output_in_json()

        # Delete Alias
        self.cmd('servicebus georecovery-alias delete  --resource-group {rg} --namespace-name {namespacenamesecondary} --alias {aliasname}')

        time.sleep(30)

        # Delete Namespace - primary
        self.cmd('servicebus namespace delete --resource-group {rg} --name {namespacenameprimary}')

        # Delete Namespace - secondary
        self.cmd('servicebus namespace delete --resource-group {rg} --name {namespacenamesecondary}')
