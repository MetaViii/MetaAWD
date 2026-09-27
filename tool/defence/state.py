class StateManager:
    def __init__(self):
        self.is_ssh = False
        self.hostname = ''
        self.port = 0
        self.username = ''
        self.password = ''
        self.active_ip = []
        self.remote_waf_dir = '/var/www/html/.phpwaf'
        self.remote_waf_path = '/var/www/html/.phpwaf/waf.php'
        self.remote_waf_log_dir = '/tmp/.phpwaf_logs'
        self.local_waf_log_dir = ''
        self.waf_deployed = False
        self.waf_guard_enabled = False
        self.waf_mode = 1
        self.waf_strict_level = 3
        self.waf_redirect_path = ''


state_manager = StateManager()
