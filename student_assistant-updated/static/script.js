console.log("✅ Student Assistant Loaded");

// Optional: simple client-side interactions
document.addEventListener("DOMContentLoaded", () => {
  const links = document.querySelectorAll("header a");
  links.forEach(link => {
    if (link.href === window.location.href) {
      link.classList.add("active");
    }
  });
});
