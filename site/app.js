(function () {
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var rows = document.querySelectorAll('.row');
  if (reduce) {
    rows.forEach(function (r) { r.classList.add('in'); });
    return;
  }
  rows.forEach(function (r, i) {
    setTimeout(function () { r.classList.add('in'); }, 180 + i * 220);
  });
})();
