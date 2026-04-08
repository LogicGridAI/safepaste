// popup.js — SafePaste Enterprise
'use strict';

const LICENSE_VERIFY_URL = 'https://api.safepaste.app/license';

const STORAGE_KEYS = {
  isLicensed: 'isLicensed',
  basicProtection: 'basicProtection',
  devsecMode: 'devsecMode',
  fintechShield: 'fintechShield',
  exfiltrationShield: 'exfiltrationShield',
  customWords: 'customWords',
};

const TOGGLE_DEFAULTS = {
  [STORAGE_KEYS.basicProtection]: true,
  [STORAGE_KEYS.devsecMode]: true,
  [STORAGE_KEYS.fintechShield]: true,
  [STORAGE_KEYS.exfiltrationShield]: true,
};

const TOGGLE_IDS = [
  STORAGE_KEYS.devsecMode,
  STORAGE_KEYS.fintechShield,
  STORAGE_KEYS.exfiltrationShield,
];

const POPUP_STORAGE_DEFAULTS = {
  [STORAGE_KEYS.isLicensed]: false,
  ...TOGGLE_DEFAULTS,
  [STORAGE_KEYS.customWords]: [],
  stat_vaulted: 0,
  stat_blocked: 0,
  stat_swaps: 0,
};

function $(id) {
  return document.getElementById(id);
}

/** Stable device fingerprint (hex SHA-256) for license activation limits on the Worker. */
async function getDeviceId() {
  const parts = [
    navigator.language || '',
    `${screen.width}x${screen.height}`,
    (() => {
      try {
        return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
      } catch {
        return '';
      }
    })(),
    String(navigator.hardwareConcurrency ?? ''),
  ];
  const raw = parts.join('|');
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(raw));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function showFeedback(message, type = 'success') {
  const el = $('feedback');
  if (!el) return;
  el.textContent = message;
  el.className = `show ${type}`;
  clearTimeout(showFeedback._t);
  showFeedback._t = setTimeout(() => { el.className = ''; }, 2800);
}

/** Set by DOMContentLoaded + storage listeners; read by updateStatusDot. */
let isLicensedGlobal = false;

function updateStatusDot() {
  const dot = $('status-dot');
  if (!dot) return;
  const basicOn = $('basicProtection')?.checked !== false;
  const proAny = TOGGLE_IDS.some((id) => $(id)?.checked);
  const active = isLicensedGlobal ? basicOn || proAny : basicOn;
  dot.classList.toggle('off', !active);
  dot.setAttribute(
    'aria-label',
    !isLicensedGlobal
      ? basicOn
        ? 'Basic protection on'
        : 'Protection disabled'
      : active
        ? 'Protection active'
        : 'All protection off'
  );
}

function applyStats(items) {
  const total =
    (items.stat_vaulted || 0) + (items.stat_blocked || 0) + (items.stat_swaps || 0);
  const el = $('stat-lifetime');
  if (el) el.textContent = String(total);
}

/**
 * Free: Pro-tier switches are forced unchecked + disabled (storage may still hold Pro prefs).
 * Pro: switches enabled; checked state from `items` when provided, else left as-is.
 */
function syncProTierToggles(licensed, items) {
  const basicEl = $('basicProtection');
  if (basicEl) {
    basicEl.disabled = false;
  }

  for (const id of TOGGLE_IDS) {
    const el = $(id);
    if (!el) continue;
    if (!licensed) {
      el.checked = false;
      el.disabled = true;
    } else {
      el.disabled = false;
      if (items) {
        const v = items[id];
        el.checked = typeof v === 'boolean' ? v : TOGGLE_DEFAULTS[id];
      }
    }
  }

  const ndaIn = $('nda-input');
  const ndaBtn = $('nda-add');
  if (!licensed) {
    if (ndaIn) ndaIn.disabled = true;
    if (ndaBtn) ndaBtn.disabled = true;
  } else {
    if (ndaIn) ndaIn.disabled = false;
    if (ndaBtn) ndaBtn.disabled = false;
  }
}

function renderLicensedUi(licensed, items) {
  isLicensedGlobal = licensed;
  const paywall = $('paywall');
  const proBox = $('proFeatures');
  const banner = $('pro-lock-banner');
  const subtitle = $('header-subtitle');

  if (licensed) {
    paywall?.classList.add('hidden');
    document.getElementById('upgrade-cta')?.classList.add('hidden');
    document.getElementById('get-pro-link')?.classList.add('hidden');
    document.getElementById('get-pro-sep')?.classList.add('hidden');
    if (banner) banner.style.display = 'none';
    if (subtitle) subtitle.textContent = 'Pro — Enterprise DLP';
  } else {
    paywall?.classList.remove('hidden');
    document.getElementById('upgrade-cta')?.classList.remove('hidden');
    document.getElementById('get-pro-link')?.classList.remove('hidden');
    document.getElementById('get-pro-sep')?.classList.remove('hidden');
    if (banner) {
      banner.style.display = '';
      banner.textContent = 'Pro — FinTech, NDAs & Green Lock below';
    }
    if (subtitle) subtitle.textContent = 'Free tier — upgrade for full vault';
  }
  proBox?.classList.toggle('pro-features--locked', !licensed);

  syncProTierToggles(licensed, licensed ? items : undefined);

  updateStatusDot();
}

function applyTogglesFromStorage(items) {
  const basicEl = $('basicProtection');
  if (basicEl) {
    const v = items[STORAGE_KEYS.basicProtection];
    basicEl.checked = typeof v === 'boolean' ? v : TOGGLE_DEFAULTS[STORAGE_KEYS.basicProtection];
  }
  for (const id of TOGGLE_IDS) {
    const el = $(id);
    if (!el) continue;
    const v = items[id];
    el.checked = typeof v === 'boolean' ? v : TOGGLE_DEFAULTS[id];
  }
}

function wireToggles(isLicensedGetter) {
  for (const id of TOGGLE_IDS) {
    const el = $(id);
    if (!el) continue;
    el.addEventListener('change', (e) => {
      if (!isLicensedGetter()) {
        e.target.checked = false;
        showFeedback('Unlock Pro to use enterprise toggles', 'warning');
        return;
      }
      chrome.storage.local.set({ [id]: e.target.checked });
      updateStatusDot();
    });
  }
}

function wireBasicProtection() {
  $('basicProtection')?.addEventListener('change', (e) => {
    chrome.storage.local.set({ [STORAGE_KEYS.basicProtection]: e.target.checked });
    updateStatusDot();
  });
}

function renderTags(words) {
  const ndaTags = $('nda-tags');
  if (!ndaTags) return;
  ndaTags.textContent = '';
  for (const word of words) {
    const tag = document.createElement('div');
    tag.className = 'nda-tag';
    tag.setAttribute('role', 'listitem');

    const text = document.createElement('span');
    text.className = 'nda-tag-text';
    text.textContent = word;
    text.title = word;

    const x = document.createElement('button');
    x.type = 'button';
    x.className = 'nda-tag-x';
    x.textContent = '×';
    x.setAttribute('aria-label', `Remove ${word}`);
    x.addEventListener('click', () => {
      chrome.storage.local.get({ [STORAGE_KEYS.customWords]: [] }, (items) => {
        const list = Array.isArray(items[STORAGE_KEYS.customWords])
          ? items[STORAGE_KEYS.customWords]
          : [];
        const next = list.filter((w) => w !== word);
        chrome.storage.local.set({ [STORAGE_KEYS.customWords]: next }, () => renderTags(next));
      });
    });

    tag.appendChild(text);
    tag.appendChild(x);
    ndaTags.appendChild(tag);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  let isLicensed = false;
  const licensed = () => isLicensed;

  chrome.storage.local.get(POPUP_STORAGE_DEFAULTS, (items) => {
    isLicensed = Boolean(items[STORAGE_KEYS.isLicensed]);
    applyTogglesFromStorage(items);
    renderTags(Array.isArray(items[STORAGE_KEYS.customWords]) ? items[STORAGE_KEYS.customWords] : []);
    applyStats(items);
    renderLicensedUi(isLicensed, isLicensed ? items : undefined);

    chrome.storage.local.set({
      [STORAGE_KEYS.basicProtection]: items[STORAGE_KEYS.basicProtection] !== false,
      [STORAGE_KEYS.devsecMode]: items[STORAGE_KEYS.devsecMode],
      [STORAGE_KEYS.fintechShield]: items[STORAGE_KEYS.fintechShield],
      [STORAGE_KEYS.exfiltrationShield]: items[STORAGE_KEYS.exfiltrationShield],
      [STORAGE_KEYS.customWords]: items[STORAGE_KEYS.customWords] || [],
    });
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes[STORAGE_KEYS.isLicensed]) {
      isLicensed = Boolean(changes[STORAGE_KEYS.isLicensed].newValue);
      if (isLicensed) {
        chrome.storage.local.get(POPUP_STORAGE_DEFAULTS, (items) => {
          applyTogglesFromStorage(items);
          renderLicensedUi(true, items);
        });
      } else {
        renderLicensedUi(false);
      }
    }
    if (changes[STORAGE_KEYS.basicProtection]) {
      const el = $('basicProtection');
      if (el) el.checked = changes[STORAGE_KEYS.basicProtection].newValue !== false;
      updateStatusDot();
    }
    for (const id of TOGGLE_IDS) {
      if (changes[id] && isLicensed) {
        const el = $(id);
        if (el && !el.disabled) {
          el.checked = changes[id].newValue !== false;
        }
      }
    }
    if (changes.stat_vaulted || changes.stat_blocked || changes.stat_swaps) {
      chrome.storage.local.get(
        { stat_vaulted: 0, stat_blocked: 0, stat_swaps: 0 },
        applyStats
      );
    }
  });

  wireToggles(licensed);
  wireBasicProtection();

  const unlockBtn = $('unlockProBtn');
  const licenseInput = $('licenseKeyInput');
  const paywallError = $('paywallError');

  unlockBtn?.addEventListener('click', async () => {
    const key = (licenseInput?.value || '').trim();
    paywallError.textContent = '';
    if (!key) {
      paywallError.textContent = 'Enter your license key.';
      return;
    }
    unlockBtn.disabled = true;
    try {
      const device_id = await getDeviceId();
      const res = await fetch(LICENSE_VERIFY_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ license_key: key, device_id }),
      });
      const data = await res.json().catch(() => ({}));
      if (data && data.success === true && data.tier === 'pro') {
        isLicensed = true;
        await chrome.storage.local.set({ [STORAGE_KEYS.isLicensed]: true });
        chrome.storage.local.get(POPUP_STORAGE_DEFAULTS, (items) => {
          applyTogglesFromStorage(items);
          renderLicensedUi(true, items);
        });
        showFeedback('Pro unlocked. Welcome to Enterprise mode.', 'success');
        licenseInput.value = '';
      } else {
        paywallError.textContent =
          (data && data.error) || 'Invalid license. Check your key and try again.';
      }
    } catch (err) {
      paywallError.textContent = 'Could not reach license service. Check your connection.';
    } finally {
      unlockBtn.disabled = false;
    }
  });

  const ndaInput = $('nda-input');
  const ndaAdd = $('nda-add');

  function addNdaWord() {
    if (!licensed()) {
      showFeedback('Unlock Pro to use Custom NDAs', 'warning');
      return;
    }
    const raw = (ndaInput?.value || '').trim();
    if (!raw) return;
    if (raw.length > 60) {
      showFeedback('Keyword too long (max 60)', 'warning');
      return;
    }
    chrome.storage.local.get({ [STORAGE_KEYS.customWords]: [] }, (items) => {
      const list = Array.isArray(items[STORAGE_KEYS.customWords])
        ? items[STORAGE_KEYS.customWords]
        : [];
      if (list.some((w) => w.toLowerCase() === raw.toLowerCase())) {
        showFeedback('Already in list', 'warning');
        ndaInput.value = '';
        return;
      }
      const next = [...list, raw];
      chrome.storage.local.set({ [STORAGE_KEYS.customWords]: next }, () => {
        renderTags(next);
        ndaInput.value = '';
        showFeedback('Keyword added', 'success');
      });
    });
  }

  ndaAdd?.addEventListener('click', addNdaWord);
  ndaInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addNdaWord();
    }
  });

  $('btn-clear')?.addEventListener('click', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      if (!tabId) {
        showFeedback('No active tab', 'warning');
        return;
      }
      chrome.tabs.sendMessage(tabId, { type: 'CLEAR_VAULT' }, (response) => {
        if (chrome.runtime.lastError || !response?.ok) {
          showFeedback('Content script not reachable', 'warning');
          return;
        }
        showFeedback('Vault cleared for this tab', 'success');
      });
    });
  });

  $('btn-log')?.addEventListener('click', () => {
    chrome.storage.local.get({ auditLog: [] }, ({ auditLog }) => {
      if (!auditLog.length) {
        showFeedback('No audit events', 'warning');
        return;
      }
      const recent = auditLog.slice(-20);
      const text = recent
        .map((e) => {
          const t = new Date(e.timestamp).toLocaleTimeString();
          return `[${t}] ${e.type} — ${e.matchCount} on ${e.hostname}`;
        })
        .join('\n');
      navigator.clipboard.writeText(text).then(
        () => showFeedback('Audit log copied', 'success'),
        () => showFeedback('Clipboard failed', 'warning')
      );
    });
  });

  $('btn-reset-stats')?.addEventListener('click', () => {
    chrome.storage.local.set({ stat_vaulted: 0, stat_blocked: 0, stat_swaps: 0 }, () => {
      $('stat-lifetime').textContent = '0';
      showFeedback('Stats reset', 'success');
    });
  });
});
