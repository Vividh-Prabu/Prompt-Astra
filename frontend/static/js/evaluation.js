/**
 * PROMPTASTRA - Model Evaluation JavaScript
 * Animates category benchmark progress fills and provides quadrant metrics context.
 */

document.addEventListener('DOMContentLoaded', () => {
  initEvaluation();
});

function initEvaluation() {
  const bars = document.querySelectorAll('.cat-bar-fill');
  bars.forEach(bar => {
    const targetWidth = bar.style.width;
    bar.style.width = '0%';
    setTimeout(() => {
      bar.style.transition = 'width 1s cubic-bezier(0.16, 1, 0.3, 1)';
      bar.style.width = targetWidth;
    }, 120);
  });
}
