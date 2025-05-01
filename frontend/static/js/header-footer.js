// Mobile menu toggle
const menuBtn = document.querySelector('.mobile-menu-btn');
const navLinks = document.querySelector('.nav-links');

if (menuBtn && navLinks) {
    menuBtn.addEventListener('click', () => {
        navLinks.classList.toggle('active');
    });
}

// Hero section animations
document.addEventListener('DOMContentLoaded', () => {
    const elements = document.querySelectorAll('.hero-content > *');
    elements.forEach((el, index) => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.animation = `fadeIn 0.5s ease forwards ${index * 0.2 + 0.3}s`;
    });
});

// Scroll animations for sections
const sections = document.querySelectorAll('.about-section, .team-section, .work-section');

function checkVisibility() {
    sections.forEach(section => {
        const sectionTop = section.getBoundingClientRect().top;
        const windowHeight = window.innerHeight;
        
        if (sectionTop < windowHeight * 0.75) {
            section.classList.add('visible');
        }
    });
}

// Initial check
if (sections.length > 0) {
    checkVisibility();
    // Add scroll event listener
    window.addEventListener('scroll', checkVisibility);
}

// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        
        // Close mobile menu if open
        if (navLinks) {
            navLinks.classList.remove('active');
        }
        
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth'
            });
        }
    });
});