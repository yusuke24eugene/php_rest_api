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
        password: document.getElementById("password").value
    };

    // Clear previous errors
    document.querySelectorAll('.input-field').forEach(input => {
        input.classList.remove('error');
    });
    document.querySelectorAll('.error-message').forEach(msg => {
        msg.classList.remove('show');
    });

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
            
            if (errors.username) {
                document.getElementById('usernameError').textContent = errors.username;
                document.getElementById('usernameError').classList.add('show');
                username.classList.add('error');
                document.getElementById("username").value = data.username;
            }

            if (errors.password) {
                document.getElementById('passwordError').textContent = errors.password;
                document.getElementById('passwordError').classList.add('show');
                password.classList.add('error');
            }
        }
    } catch (error) {
        // Handle network errors
        console.error("Error: ", error);
        alert("An error occurred, please try again.");
    }
}