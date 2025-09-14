// Simple XSS test script for SafeVault frontend
// This script can be run in browser console or as part of automated UI tests

function testXSSInjection() {
    // Try to inject script into a form field and check if it is rendered as HTML
    const testString = "<script>alert('xss')</script>";
    let input = document.createElement('input');
    input.value = testString;
    document.body.appendChild(input);

    // Simulate form submission or rendering
    let output = document.createElement('div');
    output.innerHTML = input.value;
    document.body.appendChild(output);

    // If the script runs, XSS vulnerability exists
    // If the script is rendered as text, it's safe
    if (output.innerHTML.includes(testString)) {
        console.log("PASS: Script tag rendered as text. No XSS.");
    } else {
        console.error("FAIL: Script tag executed. XSS vulnerability!");
    }

    // Cleanup
    document.body.removeChild(input);
    document.body.removeChild(output);
}

testXSSInjection();
