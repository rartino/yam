let SETTINGS = { username: '', requirePass: false, roomSkB64: '' };
const SETTINGS_KEY = 'secmsg_settings_v1';

export function loadSettings() {
    try {
	SETTINGS = { ...SETTINGS, ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') }
    } catch {
	SETTINGS = {}
    }
    return SETTINGS;
}
export function saveSettings() { localStorage.setItem(SETTINGS_KEY, JSON.stringify(SETTINGS)); }
