// CedarCrypt front-end.
//
// This script draws the mascot on the page. Because the image is set by the
// script, if a WAICT-aware browser blocks app.js -- because its hash no longer
// matches the manifest -- the mascot never appears. That is precisely the kind
// of tampering WAICT is designed to catch.
const img = document.getElementById('hero-image');
img.src = '/resources/cat.jpg';
document.getElementById('caption').textContent = 'Meet our mascot. Look how cute!';
