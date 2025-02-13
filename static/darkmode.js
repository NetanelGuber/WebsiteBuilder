document.addEventListener("DOMContentLoaded", function () {
    const darkModeToggle = document.getElementById("darkModeToggle");
  
    // Update button emoji based on current mode
    function updateDarkModeButton() {
      if (document.body.classList.contains("dark-mode")) {
        darkModeToggle.textContent = "☀️"; // Sun emoji for switching back to light mode
      } else {
        darkModeToggle.textContent = "🌙"; // Moon emoji for switching to dark mode
      }
    }
  
    // Apply the saved theme from localStorage
    const currentTheme = localStorage.getItem("theme");
    if (currentTheme === "dark") {
      document.body.classList.add("dark-mode");
    }
  
    updateDarkModeButton();
  
    darkModeToggle.addEventListener("click", function () {
      document.body.classList.toggle("dark-mode");
      localStorage.setItem("theme", document.body.classList.contains("dark-mode") ? "dark" : "light");
      updateDarkModeButton();
    });
  });
  