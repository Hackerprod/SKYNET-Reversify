// Script adapted from design.htm to provide navbar effects, particles, typing, and scroll animations.

// Particle Animation
function createParticles() {
	const bgAnimated = document.getElementById('bgAnimated');
	if (!bgAnimated) return;
	const particleCount = 50;
	for (let i = 0; i < particleCount; i++) {
		const particle = document.createElement('div');
		particle.className = 'particle';
		const size = Math.random() * 4 + 2;
		const x = Math.random() * window.innerWidth;
		const y = Math.random() * window.innerHeight;
		const duration = Math.random() * 20 + 10;
		const delay = Math.random() * 5;
		particle.style.width = size + 'px';
		particle.style.height = size + 'px';
		particle.style.left = x + 'px';
		particle.style.top = y + 'px';
		particle.style.background = `rgba(${Math.random() * 100 + 155}, ${Math.random() * 100 + 155}, 255, ${Math.random() * 0.5 + 0.2})`;
		particle.style.animation = `float ${duration}s ${delay}s infinite ease-in-out`;
		bgAnimated.appendChild(particle);
	}
}

createParticles();

// Navbar Scroll Effect
const navbar = document.querySelector('.navbar');
if (navbar) {
	window.addEventListener('scroll', () => {
		if (window.scrollY > 100) {
			navbar.classList.add('scrolled');
		} else {
			navbar.classList.remove('scrolled');
		}
	});
}

// Mobile Menu
const mobileMenuBtn = document.getElementById('mobileMenuBtn');
const mobileMenu = document.getElementById('mobileMenu');
const closeMobileMenu = document.getElementById('closeMobileMenu');

if (mobileMenuBtn && mobileMenu) {
	mobileMenuBtn.addEventListener('click', () => {
		mobileMenu.classList.add('active');
	});
}
if (closeMobileMenu && mobileMenu) {
	closeMobileMenu.addEventListener('click', () => {
		mobileMenu.classList.remove('active');
	});
}
if (mobileMenu) {
	document.querySelectorAll('#mobileMenu a').forEach(link => {
		link.addEventListener('click', () => {
			mobileMenu.classList.remove('active');
		});
	});
}

// Typing Effect
const typingText = document.getElementById('typingText');
if (typingText) {
	const texts = ['SKYNET Flex Grabber', 'Dylan Tech Solutions', 'Land Defenders', 'Land Defenders'];
	let textIndex = 0;
	let charIndex = 0;
	let isDeleting = false;

	function typeEffect() {
		const currentText = texts[textIndex];
		if (isDeleting) {
			typingText.textContent = currentText.substring(0, charIndex - 1);
			charIndex--;
		} else {
			typingText.textContent = currentText.substring(0, charIndex + 1);
			charIndex++;
		}

		let typeSpeed = isDeleting ? 50 : 100;

		if (!isDeleting && charIndex === currentText.length) {
			typeSpeed = 2000;
			isDeleting = true;
		} else if (isDeleting && charIndex === 0) {
			isDeleting = false;
			textIndex = (textIndex + 1) % texts.length;
			typeSpeed = 500;
		}

		setTimeout(typeEffect, typeSpeed);
	}

	typeEffect();
}

// Scroll Animations (IntersectionObserver)
if ('IntersectionObserver' in window) {
	const observerOptions = { threshold: 0.1, rootMargin: '0px 0px -50px 0px' };
	const observer = new IntersectionObserver((entries) => {
		entries.forEach(entry => {
			if (entry.isIntersecting) {
				entry.target.classList.add('active');
			}
		});
	}, observerOptions);
	document.querySelectorAll('.fade-in, .fade-in-left, .fade-in-right').forEach(el => {
		observer.observe(el);
	});
}

// Progress Bars Animation (simple)
document.addEventListener('DOMContentLoaded', () => {
	document.querySelectorAll('.progress-fill').forEach(fill => {
		const width = fill.getAttribute('data-width');
		if (width) {
			setTimeout(() => { fill.style.width = width; }, 500);
		}
	});
});

// Smooth Scroll for internal anchors
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
	anchor.addEventListener('click', function (e) {
		const href = this.getAttribute('href');
		if (!href || href === '#') return;
		const target = document.querySelector(href);
		if (target) {
			e.preventDefault();
			const offsetTop = target.offsetTop - 80;
			window.scrollTo({ top: offsetTop, behavior: 'smooth' });
		}
	});
});

// Simple load fade-in
window.addEventListener('load', () => {
	document.body.style.opacity = '0';
	setTimeout(() => {
		document.body.style.transition = 'opacity 0.5s ease';
		document.body.style.opacity = '1';
	}, 100);
});
