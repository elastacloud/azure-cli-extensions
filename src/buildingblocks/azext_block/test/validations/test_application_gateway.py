from enum import Enum
import unittest
import unittest.mock as mock

from azext_block.models import (Sku, ApplicationGatewayBuildingBlock, ApplicationGateway, FrontendIPConfiguration, BackendHttpSettings, HttpListener, RedirectConfiguration, RequestRoutingRule, WebApplicationFirewallConfiguration, Probe, SslPolicy)

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

class BackendHttpSettingsTest(unittest.TestCase):
    @mock.patch('azext_block.models.BackendHttpSettings._valid_affinity', new_callable=mock.PropertyMock)
    def test_valid_affinity_uses_validaffinities_member(self, mocked_p):
        mocked_p.return_value = ['Microsoft']
        target = BackendHttpSettings()
        self.assertTrue(target._is_valid_cookie_based_affinity("Microsoft"))

    def test_valid_affinity_match_known_Enabled(self):
        target = BackendHttpSettings()
        self.assertTrue(target._is_valid_cookie_based_affinity("Enabled"))

    def test_valid_affinity_match_known_Disabled(self):
        target = BackendHttpSettings()
        self.assertTrue(target._is_valid_cookie_based_affinity("Disabled"))

    def test_valid_affinity_doesnotmatch_unknown(self):
        target = BackendHttpSettings()
        self.assertFalse(target._is_valid_cookie_based_affinity("Elastacloud"))

    @mock.patch('azext_block.models.BackendHttpSettings._valid_protocol_types', new_callable=mock.PropertyMock)
    def test_valid_protocol_uses_validaffinities_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = BackendHttpSettings()
        self.assertTrue(target._is_valid_protocol("Elastacloud"))

    def test_valid_protocol_match_known_Http(self):
        target = BackendHttpSettings()
        self.assertTrue(target._is_valid_protocol("Http"))

    def test_valid_protocol_match_known_Https(self):
        target = BackendHttpSettings()
        self.assertTrue(target._is_valid_protocol("Https"))

    def test_valid_protocol_doesnotmatch_unknown(self):
        target = BackendHttpSettings()
        self.assertFalse(target._is_valid_protocol("Elastacloud"))

class HttpListenerTest(unittest.TestCase):
    @mock.patch('azext_block.models.HttpListener._valid_protocol_types', new_callable=mock.PropertyMock)
    def test_valid_protocol_uses_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = HttpListener()
        self.assertTrue(target._is_valid_protocol("Elastacloud"))

    def test_valid_protocol_match_known_Http(self):
        target = HttpListener()
        self.assertTrue(target._is_valid_protocol("Http"))

    def test_valid_protocol_match_known_Https(self):
        target = HttpListener()
        self.assertTrue(target._is_valid_protocol("Https"))

    def test_valid_protocol_doesnotmatch_unknown(self):
        target = HttpListener()
        self.assertFalse(target._is_valid_protocol("Elastacloud"))

class RedirectConfigurationTest(unittest.TestCase):
    @mock.patch('azext_block.models.RedirectConfiguration._redirect_types', new_callable=mock.PropertyMock)
    def test_valid_redirect_type_uses_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = RedirectConfiguration()
        self.assertTrue(target._is_valid_redirect_type("Elastacloud"))

    def test_valid_redirect_match_known_Permanent(self):
        target = RedirectConfiguration()
        self.assertTrue(target._is_valid_redirect_type("Permanent"))

    def test_valid_redirect_match_known_Found(self):
        target = RedirectConfiguration()
        self.assertTrue(target._is_valid_redirect_type("Found"))

    def test_valid_redirect_match_known_SeeOther(self):
        target = RedirectConfiguration()
        self.assertTrue(target._is_valid_redirect_type("SeeOther"))

    def test_valid_redirect_match_known_Temporary(self):
        target = RedirectConfiguration()
        self.assertTrue(target._is_valid_redirect_type("Temporary"))

    def test_valid_redirect_doesnotmatch_unknown(self):
        target = RedirectConfiguration()
        self.assertFalse(target._is_valid_redirect_type("Elastacloud"))


class RequestRoutingRuleTest(unittest.TestCase):
    @mock.patch('azext_block.models.RequestRoutingRule._valid_routing_rule_types', new_callable=mock.PropertyMock)
    def test_valid_redirect_type_uses_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = RequestRoutingRule()
        self.assertTrue(target._is_valid_routing_rule_type("Elastacloud"))

    def test_valid_redirect_match_known_Basic(self):
        target = RequestRoutingRule()
        self.assertTrue(target._is_valid_routing_rule_type("Basic"))

    def test_valid_redirect_match_known_PathBasedRouting(self):
        target = RequestRoutingRule()
        self.assertTrue(target._is_valid_routing_rule_type("PathBasedRouting"))

    def test_valid_redirect_doesnotmatch_unknown(self):
        target = RequestRoutingRule()
        self.assertFalse(target._is_valid_routing_rule_type("Elastacloud"))

class WebApplicationFirewallConfigurationTest(unittest.TestCase):
    @mock.patch('azext_block.models.WebApplicationFirewallConfiguration._valid_firewall_mode', new_callable=mock.PropertyMock)
    def test_valid_firewall_type_uses_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = WebApplicationFirewallConfiguration()
        self.assertTrue(target._is_valid_firewall_mode("Elastacloud"))

    def test_valid_firewall_type_match_known_Detection(self):
        target = WebApplicationFirewallConfiguration()
        self.assertTrue(target._is_valid_firewall_mode("Detection"))
        
    def test_valid_firewall_type_match_known_Prevention(self):
        target = WebApplicationFirewallConfiguration()
        self.assertTrue(target._is_valid_firewall_mode("Prevention"))

    def test_valid_redirect_doesnotmatch_unknown(self):
        target = WebApplicationFirewallConfiguration()
        self.assertFalse(target._is_valid_firewall_mode("Elastacloud"))

    def test_valid_rule_type_OWASP(self):
        target = WebApplicationFirewallConfiguration()
        self.assertTrue(target._is_valid_rule_type("OWASP"))

    def test_valid_rule_type_only_OWASP(self):
        target = WebApplicationFirewallConfiguration()
        self.assertFalse(target._is_valid_rule_type("Microsoft"))

class ProbeTest(unittest.TestCase):
    @mock.patch('azext_block.models.Probe._valid_protocol_types', new_callable=mock.PropertyMock)
    def test_valid_protocol_uses_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = Probe()
        self.assertTrue(target._is_valid_protocol("Elastacloud"))

    def test_valid_protocol_match_known_Http(self):
        target = Probe()
        self.assertTrue(target._is_valid_protocol("Http"))

    ## Note the documentation specifies this is correct, despite there being a different enum
    ## called ProbeProtocol which includes TCP instead of HTTPS
    def test_valid_protocol_match_known_Https(self):
        target = Probe()
        self.assertTrue(target._is_valid_protocol("Https"))

    def test_valid_redirect_doesnotmatch_unknown(self):
        target = Probe()
        self.assertFalse(target._is_valid_protocol("Elastacloud"))

class SslPolicyTest(unittest.TestCase):
    @mock.patch('azext_block.models.SslPolicy._valid_cipher_suites', new_callable=mock.PropertyMock)
    def test_valid_protocol_uses_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = SslPolicy()
        self.assertTrue(target._is_valid_cipher_suites("Elastacloud"))

    def test_valid_protocol_match_known_Set(self):
        target = SslPolicy()
        documentedValidSet = [ "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
                                , "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                                , "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
                                , "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
                                , "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
                                , "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
                                , "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
                                , "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
                                , "TLS_RSA_WITH_AES_256_GCM_SHA384"
                                , "TLS_RSA_WITH_AES_128_GCM_SHA256"
                                , "TLS_RSA_WITH_AES_256_CBC_SHA256"
                                , "TLS_RSA_WITH_AES_128_CBC_SHA256"
                                , "TLS_RSA_WITH_AES_256_CBC_SHA"
                                , "TLS_RSA_WITH_AES_128_CBC_SHA"
                                , "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                                , "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                                , "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
                                , "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
                                , "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
                                , "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
                                , "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
                                , "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
                                , "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
                                , "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
                                , "TLS_RSA_WITH_3DES_EDE_CBC_SHA"]
        for valid in documentedValidSet: self.assertTrue(target._is_valid_cipher_suites(valid))

    def test_valid_redirect_doesnotmatch_unknown(self):
        target = SslPolicy()
        self.assertFalse(target._is_valid_cipher_suites("Elastacloud"))

    @mock.patch('azext_block.models.SslPolicy._valid_ssl_protocols', new_callable=mock.PropertyMock)
    def test_valid_protocol_uses_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = SslPolicy()
        self.assertTrue(target._is_valid_ssl_protocol("Elastacloud"))

    def test_valid_protocol_match_known_Set(self):
        target = SslPolicy()
        documentedValidSet = [ "TLSv1_0",
                                "TLSv1_1",
                                "TLSv1_2"]
        for valid in documentedValidSet: self.assertTrue(target._is_valid_ssl_protocol(valid))

    def test_valid_redirect_doesnotmatch_unknown(self):
        target = SslPolicy()
        self.assertFalse(target._is_valid_ssl_protocol("Elastacloud"))

    @mock.patch('azext_block.models.SslPolicy._valid_ssl_policy_types', new_callable=mock.PropertyMock)
    def test_valid_policy_types_uses_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = SslPolicy()
        self.assertTrue(target._is_valid_ssl_policy_type("Elastacloud"))

    def test_valid_policy_types_match_known_Set(self):
        target = SslPolicy()
        documentedValidSet = [ "Predefined",
                                "Custom" ]
        for valid in documentedValidSet: self.assertTrue(target._is_valid_ssl_policy_type(valid))

    def test_valid_policy_types_doesnotmatch_unknown(self):
        target = SslPolicy()
        self.assertFalse(target._is_valid_ssl_policy_type("Elastacloud"))

    @mock.patch('azext_block.models.SslPolicy._valid_ssl_policy_names', new_callable=mock.PropertyMock)
    def test_valid_policy_types_uses_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = SslPolicy()
        self.assertTrue(target._is_valid_ssl_policy_name("Elastacloud"))

    def test_valid_policy_types_match_known_Set(self):
        target = SslPolicy()
        documentedValidSet = [ "AppGwSslPolicy20150501",
                                "AppGwSslPolicy20170401",
                                "AppGwSslPolicy20170401S" ]
        for valid in documentedValidSet: self.assertTrue(target._is_valid_ssl_policy_name(valid))

    def test_valid_policy_types_doesnotmatch_unknown(self):
        target = SslPolicy()
        self.assertFalse(target._is_valid_ssl_policy_name("Elastacloud"))