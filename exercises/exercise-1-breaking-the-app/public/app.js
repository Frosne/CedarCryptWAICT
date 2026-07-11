// CedarCrypt front-end.
//
// The image shown on the page is decided by the server (see /api/image and the
// admin console). This script just fetches that choice and renders it.
//
// Note for Exercise 2: because the whole page depends on this script running,
// tampering with app.js breaks the site. That is precisely the class of attack
// WAICT catches -- a manifest hash that no longer matches blocks the script.
(async function () {
  const img = document.getElementById('hero-image');
  const caption = document.getElementById('caption');
  try {
    const res = await fetch('/api/image');
    const { image } = await res.json();
    img.src = '/resources/' + image;
    caption.textContent =
      image === 'evil.jpg'
        ? '⚠️ This is NOT the cat you were promised.'
        : 'Meet our mascot. Look how cute!';
  } catch (e) {
    caption.textContent = 'Could not load the image.';
  }
})();
