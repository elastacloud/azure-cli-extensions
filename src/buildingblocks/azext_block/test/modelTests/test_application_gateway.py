from enum import Enum
import unittest
import unittest.mock as mock

from azext_block.models import (Sku, ApplicationGatewayBuildingBlock, ApplicationGateway, FrontendIPConfiguration)

class MockSkus(Enum):
    small = 'Standard_Big'

class SkuTest(unittest.TestCase):
    @mock.patch('azext_block.models.Sku._valid_tiers', new_callable=mock.PropertyMock)
    def test_valid_tiers_uses_validtiers_member(self, mocked_p):
        mocked_p.return_value = ['Frog']
        target = Sku()
        self.assertTrue(target._is_valid_tier("Frog"))

    def test_valid_tiers_match_known_WAF(self):
        target = Sku()
        self.assertTrue(target._is_valid_tier("WAF"))

    def test_valid_tiers_match_known_Standard(self):
        target = Sku()
        self.assertTrue(target._is_valid_tier("Standard"))


    @mock.patch('azext_block.models.Sku._valid_sizes', new_callable=mock.PropertyMock)
    def test_valid_sizes_uses_validsizes_member(self, mocked_p):
        mocked_p.return_value = ['Standard_Big', 'Standard_Mocks']
        target = Sku()
        self.assertTrue(target._is_valid_sku("Big"))

    def test_valid_sizes_match_known_Small(self):
        target = Sku()
        self.assertTrue(target._is_valid_sku("Small"))

    def test_valid_sizes_match_known_Medium(self):
        target = Sku()
        self.assertTrue(target._is_valid_sku("Medium"))

    def test_valid_sizes_match_known_Large(self):
        target = Sku()
        self.assertTrue(target._is_valid_sku("Large"))

    def test_valid_capacity_must_be_positive(self):
        target = Sku()
        self.assertFalse(target._is_valid_capacity(-1))

    def test_valid_capacity_cannot_be_zero(self):
        target = Sku()
        self.assertFalse(target._is_valid_capacity(0))

    def test_valid_capacity_cannot_be_gt_10(self):
        target = Sku()
        self.assertFalse(target._is_valid_capacity(11))

class FrontendIPConfigurationTest(unittest.TestCase):
    def test_is_Public_valid_gateway_type(self):
        target = FrontendIPConfiguration(application_gateway_type='Public')
        self.assertTrue(target._is_valid_gateway_type("Public"))

    def test_is_Private_valid_gateway_type(self):
        target = FrontendIPConfiguration(application_gateway_type='Internal')
        self.assertTrue(target._is_valid_gateway_type("Internal"))

    def test_is_Frog_invalid_gateway_type(self):        
        target = FrontendIPConfiguration(application_gateway_type='Frog')
        self.assertFalse(target._is_valid_gateway_type("Frog"))

    def test_is_valid_gateway_type_irrelevant_to_current(self):        
        target = FrontendIPConfiguration(application_gateway_type='Internal')
        self.assertTrue(target._is_valid_gateway_type("Public"))
