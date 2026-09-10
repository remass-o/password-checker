"""
Unit tests for password_checker module.
"""

import unittest
from unittest.mock import patch, MagicMock
import password_checker


class TestPasswordChecker(unittest.TestCase):
    """Test cases for password checker functions."""
    
    def test_get_password_leaks_count_found(self):
        """Test when password hash is found in leaked hashes."""
        mock_response = MagicMock()
        mock_response.text = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:1\n2D1E2C5B7A8F1C9D0E4A3B2C1D5F8E9A0B:5"
        
        result = password_checker.get_password_leaks_count(
            mock_response, 
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        )
        self.assertEqual(result, 1)
    
    def test_get_password_leaks_count_not_found(self):
        """Test when password hash is not found in leaked hashes."""
        mock_response = MagicMock()
        mock_response.text = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:1\n2D1E2C5B7A8F1C9D0E4A3B2C1D5F8E9A0B:5"
        
        result = password_checker.get_password_leaks_count(
            mock_response, 
            "NONEXISTENTHASH123456789ABCDEF0123"
        )
        self.assertEqual(result, 0)
    
    def test_pwned_api_check_returns_int(self):
        """Test that pwned_api_check returns an integer."""
        with patch('password_checker.request_api_data') as mock_request:
            mock_response = MagicMock()
            mock_response.text = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:1"
            mock_request.return_value = mock_response
            
            result = password_checker.pwned_api_check("testpassword")
            self.assertIsInstance(result, int)
    
    @patch('password_checker.request_api_data')
    def test_request_api_data_success(self, mock_get):
        """Test successful API request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "HASH:COUNT"
        mock_get.return_value = mock_response
        
        result = password_checker.request_api_data("12345")
        self.assertEqual(result.status_code, 200)
    
    @patch('password_checker.request_api_data')
    def test_request_api_data_failure(self, mock_get):
        """Test API request failure handling."""
        mock_get.side_effect = RuntimeError("Network error")
        
        with self.assertRaises(RuntimeError):
            password_checker.request_api_data("12345")


if __name__ == "__main__":
    unittest.main()
