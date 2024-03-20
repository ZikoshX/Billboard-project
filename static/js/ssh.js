var slideIndex = 1;
showSlides(slideIndex);
var slides, timer;

function plusSlides(n) {
  clearTimeout(timer); // Reset the timer on manual navigation
  showSlides(slideIndex += n);
}

function currentSlide(n) {
  clearTimeout(timer); // Reset the timer on manual navigation
  showSlides(slideIndex = n);
}

function showSlides(n) {
  var i;
  slides = document.getElementsByClassName("mySlides");
  if (n > slides.length) {slideIndex = 1}
  if (n < 1) {slideIndex = slides.length}
  for (i = 0; i < slides.length; i++) {
      slides[i].style.display = "none";
  }
  slides[slideIndex-1].style.display = "block";
  timer = setTimeout(function(){ plusSlides(1) }, 4000); // Change slide every 3 seconds
}