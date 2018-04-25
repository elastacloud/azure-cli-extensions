import unittest
import unittest.mock as mock

from azext_block.models import (Sku, ApplicationGatewayBuildingBlock, ApplicationGateway, FrontendIPConfiguration, BackendHttpSettings, HttpListener, RedirectConfiguration, RequestRoutingRule, WebApplicationFirewallConfiguration, Probe, SslPolicy)

class SkuTests(unittest.TestCase):
    def test_initializer_defaults(self):
        target = Sku()
        self.assertEqual(target.tier, "Standard")

    def test_initializer_defaults_size(self):
        target = Sku()
        self.assertEqual(target.size, "Small")

    def test_initializer_defaults_size_medium_for_WAF(self):
        target = Sku(tier="WAF")
        self.assertEqual(target.size, "Medium")

    def test_transform_formats_name(self):        
        target = Sku()
        model = target.transform()
        self.assertEqual(model.name, "Standard_Small")