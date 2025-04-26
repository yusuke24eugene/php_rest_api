/*const hamburger = document.getElementById("hamburger");
const navLinks = document.querySelector(".nav-links");

// Toggle the 'active' class on the navbar links when the hamburger icon is clicked
hamburger.addEventListener("click", () => {
  navLinks.classList.toggle("active");
});*/

// Get the current year dynamically and set it in the footer
const yearElement = document.getElementById("year");
const currentYear = new Date().getFullYear();
yearElement.textContent = currentYear;

async function submitForm(event) {
    event.preventDefault();  // Prevent default form submission

    // Prepare the data you want to send
    let data = {
        username: document.getElementById("username").value,
        email: document.getElementById("email").value,
        firstName: document.getElementById("firstName").value,
        lastName: document.getElementById("lastName").value,
        birthDate: document.getElementById("birthDate").value,
        password: document.getElementById("password").value,
        confirmPassword: document.getElementById("confirmPassword").value
    };

    // Clear previous errors
    document.querySelectorAll('.input-field').forEach(input => {
        input.classList.remove('error');
    });
    document.querySelectorAll('.error-message').forEach(msg => {
        msg.classList.remove('show');
    });

    const bearerToken = localStorage.getItem('access_token');
    const apiUrl = "http://localhost/php_rest_api/index.php/";

    const searchParams = new URLSearchParams(window.location.search);
    id = searchParams.get('id');

    try {
        // Send the POST request using fetch
        let response = await fetch(apiUrl + id, {
            method: "PUT",
            headers: {
                "Authorization": `Bearer ${bearerToken}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)  // Convert data to JSON
        });

        // Check if the response status is OK (status 200)
        if (response.ok) {
            // Parse the JSON response
            let jsonResponse = await response.json();
            console.log("Response from API: ", jsonResponse);

            let data = {
                username: document.getElementById("username").value,
                password: document.getElementById("password").value
            };

            // Handle the response (e.g., show a success message or redirect)
            try {
                // Send the POST request using fetch
                let response = await fetch("http://localhost/php_rest_api/index.php/login", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(data)  // Convert data to JSON
                });
                
                // Check if the response status is OK (status 200)
                if (response.ok) {
                    // Parse the JSON response
                    let jsonResponse = await response.json();
                    console.log("Response from API: ", jsonResponse);
        
                    // Handle the response (e.g., show a success message or redirect)
                    // Save Bearer Token in localStorage
                    localStorage.setItem('access_token', jsonResponse.token);
                    window.location.href = 'index.html';
                } else {
                    // Handle error if the response is not OK
                    let errors = await response.json();
                    window.location.href = 'login.html';
                }
            } catch (error) {
                // Handle network errors
                console.error("Error: ", error);
                alert("An error occurred, please try again.");
                window.location.href = 'login.html';
            }
        } else {
            // Handle error if the response is not OK
            let errors = await response.json();
            
            if (errors.username) {
                document.getElementById('usernameError').textContent = errors.username;
                document.getElementById('usernameError').classList.add('show');
                username.classList.add('error');
                document.getElementById("username").value = data.username;
            }

            if (errors.email) {
                document.getElementById('emailError').textContent = errors.email;
                document.getElementById('emailError').classList.add('show');
                email.classList.add('error');
                document.getElementById("email").value = data.email;
            }

            if (errors.firstName) {
                document.getElementById('firstNameError').textContent = errors.firstName;
                document.getElementById('firstNameError').classList.add('show');
                firstName.classList.add('error');
                document.getElementById("firstName").value = data.firstName;
            }

            if (errors.lastName) {
                document.getElementById('lastNameError').textContent = errors.lastName;
                document.getElementById('lastNameError').classList.add('show');
                lastName.classList.add('error');
                document.getElementById("lastName").value = data.lastName;
            }

            if (errors.birthDate) {
                document.getElementById('birthDateError').textContent = errors.birthDate;
                document.getElementById('birthDateError').classList.add('show');
                birthDate.classList.add('error');
                document.getElementById("birthDate").value = data.birthDate;
            }

            if (errors.password) {
                document.getElementById('passwordError').textContent = errors.password;
                document.getElementById('passwordError').classList.add('show');
                password.classList.add('error');
            }

            if (errors.confirmPassword) {
                document.getElementById('confirmPasswordError').textContent = errors.confirmPassword;
                document.getElementById('confirmPasswordError').classList.add('show');
                confirmPassword.classList.add('error');
            }
        }
    } catch (error) {
        // Handle network errors
        console.error("Error: ", error);
        //window.location.href = 'login.html';
    }
}

function fillFormData() {
    document.querySelector('#username').value = sessionStorage.getItem('username');
    document.querySelector('#email').value = sessionStorage.getItem('email');
    document.querySelector('#firstName').value = sessionStorage.getItem('firstName');
    document.querySelector('#lastName').value = sessionStorage.getItem('lastName');
    document.querySelector('#birthDate').value = sessionStorage.getItem('birthDate');
}

window.onload = fillFormData;