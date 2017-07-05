import unittest

from mock import MagicMock, Mock, patch, PropertyMock, call


@patch('hmac.new')
class XHubSignatureMiddlewareTestSuite(unittest.TestCase):
    
    def setUp(self):
        with patch('django.http.HttpResponse'):
            with patch ('django.conf.settings'):
                import middleware

                self.get_response = MagicMock()
                self.middleware = middleware.XHubSignatureMiddleware(self.get_response)

        self.request = MagicMock()
    
    
    def test_get_response_called_if_not_hub_request(self, hmac_new):
        self.request.META.get.return_value = None
        self.middleware.__call__(self.request)
        assert call(self.request,) == self.get_response.call_args

    
    def test_get_response_called_if_verified(self, hmac_new):
        self.request.META.get.return_value = 'sha1=test_signature'
        hmac_new.return_value.hexdigest.return_value = 'test_signature'
        self.middleware.__call__(self.request)
        assert call(self.request,) == self.get_response.call_args
    
    
    def test_get_signature_header_from_request(self, hmac_new):
        self.middleware.__call__(self.request)
        assert call('HTTP_X_HUB_SIGNATURE', None,) == self.request.META.get.call_args

    
    def test_bypass_if_not_hub_request(self, hmac_new):
        self.request.META.get.return_value = None
        self.middleware.__call__(self.request)
        assert not self.request.body.encode.call_args
        assert not hmac_new.call_args

    
    def test_hmac_called(self, hmac_new):
        self.request.META.get.return_value = 'test_signature'
        self.middleware.__call__(self.request)
        assert hmac_new.called


if __name__ == '__main__':
    unittest.main()
