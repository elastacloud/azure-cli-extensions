from enum import Enum
import unittest
import unittest.mock as mock

from azext_block.models import (Sku, ApplicationGatewayBuildingBlock, ApplicationGateway, FrontendIPConfiguration)
   
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


class MockSkus(Enum):
    small = 'Standard_Big'

class mockingNamespaces(unittest.TestCase):
    @mock.patch('azext_block.models.Sku._valid_sizes', new_callable=mock.PropertyMock)
    def test_with_cstr(self, mocked_p):
        mocked_p.return_value = ['Standard_Big', 'Standard_Mocks']
        target = Sku()
        self.assertTrue(target._is_valid_sku("Big"))

