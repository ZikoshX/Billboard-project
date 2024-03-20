let slideIndexx = 0;
const slidess = document.getElementsByClassName("feedback-slide");
const totalSlides = slidess.length;

// Update the slide number text
function updateSlideNumberr() {
  const slideNumberElement = document.querySelector('.slide-number');
  slideNumberElement.textContent = `${slideIndexx + 1} / ${totalSlides}`;
}

// Next/previous controls
function moveSlidee(n) {
  slideIndexx += n;
  if (slideIndexx > totalSlides - 1) slideIndexx = 0;
  if (slideIndexx < 0) slideIndexx = totalSlides - 1;
  showSlidess(slideIndexx);
}

function showSlidess(n) {
  // Hide all slides
  for (let i = 0; i < slidess.length; i++) {
    slidess[i].style.display = "none";  
  }
  // Show the current slide
  slidess[n].style.display = "block";
  updateSlideNumberr();
}

// Initialize the slideshow
document.addEventListener('DOMContentLoaded', function() {
  showSlidess(slideIndexx);
});