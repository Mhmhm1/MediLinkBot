// MediLink - JavaScript for interactive features

document.addEventListener('DOMContentLoaded', function() {
    
    // Add smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Form validation enhancement
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!form.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // Symptom Search and Filter
    const symptomSearch = document.getElementById('symptomSearch');
    const symptomItems = document.querySelectorAll('.symptom-item');
    const noResults = document.getElementById('noResults');
    const selectedCountSpan = document.getElementById('selectedCount');
    
    if (symptomSearch && symptomItems.length > 0) {
        // Update selected count
        const updateCounter = () => {
            const selectedCount = document.querySelectorAll('.symptom-checkbox:checked').length;
            if (selectedCountSpan) {
                selectedCountSpan.textContent = selectedCount;
            }
        };

        // Filter symptoms based on search
        symptomSearch.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase().trim();
            let visibleCount = 0;

            symptomItems.forEach(item => {
                const symptomText = item.getAttribute('data-symptom');
                if (symptomText.includes(searchTerm)) {
                    item.style.display = '';
                    visibleCount++;
                } else {
                    item.style.display = 'none';
                }
            });

            // Show/hide no results message
            if (visibleCount === 0 && searchTerm !== '') {
                noResults.style.display = 'block';
            } else {
                noResults.style.display = 'none';
            }
        });

        // Update counter when checkboxes change
        const symptomCheckboxes = document.querySelectorAll('.symptom-checkbox');
        symptomCheckboxes.forEach(checkbox => {
            checkbox.addEventListener('change', updateCounter);
        });

        // Initial counter update
        updateCounter();
    }

    // Auto-expand textarea
    const customSymptomsTextarea = document.getElementById('custom_symptoms');
    if (customSymptomsTextarea) {
        customSymptomsTextarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
    }

    // Animate progress bars on results page
    const progressBars = document.querySelectorAll('.progress-bar');
    if (progressBars.length > 0) {
        setTimeout(() => {
            progressBars.forEach(bar => {
                const width = bar.style.width;
                bar.style.width = '0';
                setTimeout(() => {
                    bar.style.transition = 'width 1s ease-out';
                    bar.style.width = width;
                }, 100);
            });
        }, 200);
    }

    // Confirm before printing
    const printButtons = document.querySelectorAll('[onclick="window.print()"]');
    printButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            // Add a small delay to ensure the page is ready
            setTimeout(() => {
                window.print();
            }, 100);
        });
    });

    // Add animation to cards on load
    const cards = document.querySelectorAll('.card');
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        setTimeout(() => {
            card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 100);
    });

    // Highlight selected specialist option
    const specialistRadios = document.querySelectorAll('input[name="selected_disease"]');
    specialistRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            document.querySelectorAll('.specialist-option').forEach(option => {
                option.style.backgroundColor = '';
            });
            if (this.checked) {
                this.closest('.specialist-option').style.backgroundColor = '#e6f2ff';
            }
        });
    });

    // Initialize selected specialist highlight
    const checkedSpecialist = document.querySelector('input[name="selected_disease"]:checked');
    if (checkedSpecialist) {
        checkedSpecialist.closest('.specialist-option').style.backgroundColor = '#e6f2ff';
    }

    // Doctor card selection
    const doctorCards = document.querySelectorAll('.doctor-card');
    doctorCards.forEach(card => {
        card.addEventListener('click', function() {
            // Remove selected class from all cards
            doctorCards.forEach(c => c.classList.remove('selected'));
            // Add selected class to clicked card
            this.classList.add('selected');
            // Check the radio button
            const radio = this.querySelector('input[type="radio"]');
            if (radio) {
                radio.checked = true;
            }
        });
    });

    // Initialize selected doctor card
    const selectedDoctorRadio = document.querySelector('input[name="selected_doctor"]:checked');
    if (selectedDoctorRadio) {
        selectedDoctorRadio.closest('.doctor-card').classList.add('selected');
    }
});
