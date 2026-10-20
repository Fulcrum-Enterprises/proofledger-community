// src/caps.js — the monthly allowance. PROOF_MONTHLY_CAP proofs per account per calendar
// month through the API; 0 (the default) means no limit. Counted from the proofs table,
// so a restart or a manual edit cannot drift it.
'use strict';

const CAP = Math.max(0, parseInt(process.env.PROOF_MONTHLY_CAP || '0', 10) || 0);

function init({ db }) {
  const count = db.prepare(`SELECT COUNT(*) AS n FROM proofs WHERE user_id = ? AND created_at >= ?`);
  function usedThisMonth(userId) {
    const month = new Date().toISOString().slice(0, 7);
    return count.get(userId, `${month}-01`).n;
  }
  // Infinity when there is no cap, so `used >= cap` is simply never true.
  const monthlyCap = () => (CAP > 0 ? CAP : Infinity);
  const capHint = () => (CAP > 0 ? `This server allows ${CAP.toLocaleString('en-US')} proofs per account per month.` : '');
  return { usedThisMonth, monthlyCap, capHint, CAP };
}

module.exports = { init };
