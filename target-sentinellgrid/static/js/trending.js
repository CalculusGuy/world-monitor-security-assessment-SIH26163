// INTENTIONALLY VULNERABLE: reflected DOM XSS.
// The 'topic' query param is written straight into innerHTML with no
// escaping, so a payload like ?topic=<img src=x onerror=alert(1)> executes.
(function () {
  const params = new URLSearchParams(window.location.search);
  const topic = params.get('topic');
  if (topic) {
    const el = document.getElementById('pinned-topic');
    el.innerHTML = '📌 Pinned: ' + topic;
  }
})();
