"""
Tests for Configuration Management
==================================

Run with: pytest tests/
"""

import pytest
import tempfile
import os

from tds_proxy.config import (
    load_config, parse_config, create_sample_config,
    save_sample_config, load_config_with_env
)
from tds_proxy.backend import DatabaseType
from tds_proxy.proxy import ProxyMode


class TestParseConfig:
    """Tests for configuration parsing"""
    
    def test_parse_minimal_config(self):
        """Test parsing minimal configuration"""
        data = {
            'proxy': {
                'port': 5000
            },
            'backends': {
                'test_ase': {
                    'host': 'localhost',
                    'port': 5000
                }
            }
        }
        
        config = parse_config(data)
        
        assert config.listen_port == 5000
        assert 'test_ase' in config.backends
        assert config.backends['test_ase'].host == 'localhost'
    
    def test_parse_full_config(self):
        """Test parsing full configuration"""
        data = {
            'proxy': {
                'host': '127.0.0.1',
                'port': 6000,
                'server_name': 'MyProxy',
                'default_backend': 'primary',
                'mode': 'intercept',
                'max_clients': 50,
                'client_timeout': 1800,
                'log_queries': True,
                'log_level': 'DEBUG'
            },
            'backends': {
                'primary': {
                    'host': 'ase.example.com',
                    'port': 5000,
                    'type': 'ase',
                    'database': 'master',
                    'ssl': True,
                    'ssl_verify': False,
                    'connect_timeout': 60,
                    'read_timeout': 600,
                    'charset': 'latin1'
                },
                'analytics': {
                    'host': 'iq.example.com',
                    'port': 2638,
                    'type': 'iq'
                }
            }
        }
        
        config = parse_config(data)
        
        assert config.listen_host == '127.0.0.1'
        assert config.listen_port == 6000
        assert config.server_name == 'MyProxy'
        assert config.default_backend == 'primary'
        assert config.mode == ProxyMode.INTERCEPT
        assert config.max_clients == 50
        assert config.log_queries is True
        
        # Check backends
        assert len(config.backends) == 2
        
        primary = config.backends['primary']
        assert primary.host == 'ase.example.com'
        assert primary.database_type == DatabaseType.ASE
        assert primary.use_ssl is True
        assert primary.ssl_verify is False
        assert primary.connect_timeout == 60
        
        analytics = config.backends['analytics']
        assert analytics.database_type == DatabaseType.IQ


class TestLoadConfig:
    """Tests for loading configuration from file"""
    
    def test_load_config_from_file(self):
        """Test loading configuration from YAML file"""
        config_content = """
proxy:
  port: 5001

backends:
  test:
    host: testhost
    port: 5000
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name

        try:
            config = load_config(temp_path)
            assert config.listen_port == 5001
            assert 'test' in config.backends
        finally:
            os.unlink(temp_path)
    
    def test_load_config_with_env_vars(self):
        """Test loading configuration with environment variable substitution"""
        config_content = """
proxy:
  port: 5000

backends:
  test:
    host: ${TEST_DB_HOST:-localhost}
    port: ${TEST_DB_PORT:-5000}
"""

        # Set environment variable
        os.environ['TEST_DB_HOST'] = 'env-host.example.com'

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name

        try:
            config = load_config_with_env(temp_path)
            assert config.backends['test'].host == 'env-host.example.com'
            assert config.backends['test'].port == 5000  # Default
        finally:
            os.unlink(temp_path)
            del os.environ['TEST_DB_HOST']


class TestSampleConfig:
    """Tests for sample configuration generation"""
    
    def test_create_sample_config(self):
        """Test sample configuration generation"""
        sample = create_sample_config()
        
        assert isinstance(sample, str)
        assert 'proxy:' in sample
        assert 'backends:' in sample
        assert 'host:' in sample
        assert 'port:' in sample
    
    def test_save_sample_config(self):
        """Test saving sample configuration to file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            pass  # Just create the file
        
        try:
            save_sample_config(f.name)
            
            # Verify file was written
            assert os.path.exists(f.name)
            
            # Verify it can be loaded
            config = load_config(f.name)
            assert config is not None
            assert len(config.backends) > 0
        finally:
            os.unlink(f.name)


class TestBackendConfig:
    """Tests for backend configuration"""
    
    def test_backend_defaults(self):
        """Test backend configuration defaults"""
        data = {
            'proxy': {},
            'backends': {
                'minimal': {
                    'host': 'db.example.com',
                    'port': 5000
                }
            }
        }
        
        config = parse_config(data)
        backend = config.backends['minimal']
        
        assert backend.database_type == DatabaseType.ASE
        assert backend.default_database == ''
        assert backend.use_ssl is False
        assert backend.ssl_verify is True
        assert backend.connect_timeout == 30.0
        assert backend.read_timeout == 300.0
        assert backend.packet_size == 4096
        assert backend.charset == 'utf8'
    
    def test_backend_credentials_override(self):
        """Test backend credential override"""
        data = {
            'proxy': {},
            'backends': {
                'with_creds': {
                    'host': 'db.example.com',
                    'port': 5000,
                    'username': 'proxy_user',
                    'password': 'proxy_pass'
                }
            }
        }
        
        config = parse_config(data)
        backend = config.backends['with_creds']
        
        assert backend.username == 'proxy_user'
        assert backend.password == 'proxy_pass'


class TestProxyConfig:
    """Tests for proxy configuration"""
    
    def test_proxy_defaults(self):
        """Test proxy configuration defaults"""
        data = {
            'backends': {
                'test': {
                    'host': 'localhost',
                    'port': 5000
                }
            }
        }
        
        config = parse_config(data)
        
        assert config.listen_host == '0.0.0.0'
        assert config.listen_port == 5000
        assert config.mode == ProxyMode.TRANSPARENT
        assert config.server_name == 'TDS_Proxy'
        assert config.max_clients == 100
        assert config.log_queries is False
    
    def test_proxy_modes(self):
        """Test different proxy modes"""
        for mode_str in ['transparent', 'intercept', 'multiplex']:
            data = {
                'proxy': {'mode': mode_str},
                'backends': {'test': {'host': 'localhost', 'port': 5000}}
            }
            
            config = parse_config(data)
            assert config.mode == ProxyMode(mode_str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
