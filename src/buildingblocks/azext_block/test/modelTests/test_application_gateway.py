import unittest
from unittest.mock import MagicMock
from azext_block.models import (ApplicationGatewayBuildingBlock, ApplicationGateway)

class ApplicationGatewayTest(unittest.TestCase):
    _staticRG = frozenset(["resourceGroup1", "resourceGroup2"])
    _settings = [ApplicationGateway(subscription_id="b33f13", frontend_ip_configurations=[
        {
            "frontendIPConfigurations": [{ 
                "name" : "sampleIPConfig", 
                "applicationGatewayType": "Public" 
            }]
    }])]

    def setUp(self):
        self.target = ApplicationGatewayBuildingBlock(self._settings)
        self.target.proxy_extract_resource_groups = MagicMock(return_value=self._staticRG)

    def test_transform_uses_settings(self):
        resultRG, _ = self.target.transform()
        self.assertCountEqual(resultRG, self._staticRG)