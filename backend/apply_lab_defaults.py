"""Apply the established lab topology without changing saved credentials."""
from app import create_app
from app.utils.helpers import set_setting


LAB_SETTINGS = {
    'wazuh_host': '127.0.0.1',
    'wazuh_api_port': '55000',
    'wazuh_indexer_port': '9200',
    'wazuh_api_user': 'wazuh',
    'wazuh_indexer_user': 'admin',
    'pfsense_host': 'https://10.10.10.1',
    'pfsense_alias_name': 'SOC_Blocklist',
    'pfsense_block_interface': 'wan',
    'alert_threshold_level': '10',
    'polling_interval_seconds': '60',
    'whitelist_ips': '127.0.0.1,10.10.10.0/24,192.168.1.0/24',
}


def main():
    app = create_app(start_scheduler=False)
    with app.app_context():
        for key, value in LAB_SETTINGS.items():
            set_setting(key, value, updated_by='lab-topology-script')
    print('Lab topology applied. Saved Wazuh passwords and pfSense API key were preserved.')
    print('Auto-response was not enabled. Test both connections before enabling it.')


if __name__ == '__main__':
    main()
