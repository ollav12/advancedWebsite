# Assigment 2 - Olav Høysæther Opheim

## Task 2a
## 1 - Find a way to do an SQL injection attack against the app.
I was able to find a way to use an SQL injection to attack the app and create a new user using the login form. I used basic SQL code to create a new user. I was able to construct the sql query by looking at how the database table users was setup in the app.py, and also by using the VScode exstention SQLite.

## 2 - Describe briefly how you did it
I used the following command:
'INSERT INTO users('username', 'password', 'info') VALUES ('Hacker12', 'password', '{"color": "red", "other_info": "You just got hacked!"}');

## 3 - Fix the code in app.py so that it's no longer vulnerable to SQL injections
I fixed the code by checking the input a user provides in the login form.



## Task 2b
## 1 & 2- Find a way to inject JavaScript code into the home page, and describe how you did it.
I was able to find a way to inject JavaScript code into the home page by editing the About field on my profile. By inputting and saving a simnple JS code in the about field i was able to make the code run when you view the user's about field.
Here is the script i inputted: <b onmouseover=alert('Hacked!')>click me!</b>

## 3 - Could we solve (some of) the injection problems with a restrictive Content Security Policy? Explain.
Yes, by implementing a Content Security Policy(CSP) we could mitigate some of the injection problems. CSP would especially work well to mitigate XSS attacks. By implementing CSP we could control which scripts that can be executed on the website. By defining some rules that specify the srouces where the content can be loaded and executed from. 

## 4 - Try visiting /users/me in the browser. Does you code injection still work? Explain.
No, when accessing /users/me the injection does not work, the code is just displayed in plain and not executed. The reason for this is becuase the server is rendering the user data as HTML instead of retruning the data as JSON. By returining data as HTML it is likely sanitized and processed by the template (users.html), before being displayed on the web page "/users/me".


## 5 - Fix the code injection problem you find in script.js
I have fixed the injection problem by creating a sanitize function to filter out
symbols that can cuase injection. I tried to implement the fix by using uhtml, but was not able to fix it that way. 


## Task 2c
## 1 - Is this in line with security best practices? Explain.
How are passwords stored, and are they stored safely:
Passwords are stored inside the database without any hashing or encryption. These passwords are not stored safely. I was able to see this by using the SQLite VScode extension and make an SQL query to retrive user passwords.

Can a user chage to an empty password:
I was able to change password to " ", which is by my definition empty as it is just one space. This is not  good practise when it comes to security.

Are there any checks to see if changed password is strong and is this good practise:
No, there are no checks to see if the password is strong. It is good practise to check if the password is: long enough, multiple symbols, numbers, capital letters etc.

## 2 - Implement safer password stroage. (Minimum hash with salt)
Implemented safer password storage by using hashlib to create and calculate hash. The database now stores hash and salt instead of password, and when user tryes to login we validate if the scrypt() hash calculated with the salt from the db matches the salt stored in the db for that user. We now have safer password storing. I used the library hashlib to perform hashing.

## 3 - Implement some form of checking of new passwords.
Password checking is implemented by editing the profile_form.py. Here we check if the password is long enough, has enough numbers, special characters etc. Changing to a new password is not working correctly (was not able to figure out the bug), but the password checking works.

## 4 - Implement some form of simple access control scheme.
Implemented simple access control scheme where users that are admin can access /users/. The problem is that if a user is not admin, no users are displayed at the home page. Not the best implemitation but it is some for of access control, issue is that with the current code all users are set as admins by default. Change the value to False in the app.y under Class user "self.is_admin = user_data.get("is_admin", False)". When editing the is_admin bool value you have to delete the users.db and reload the website for it to take affect.

## 5 - Is it possible for a user to change another user's profile information? Check this, and explain why/why not.
At this point i have not been able to find a way for another users to change profile information for other users.


## Task 2d
## 1 - Notes of possible vulnerabilities, and uncertain about best practices. Implement small fixes if it is possible in reasonable amout of time.

Possible vulnerabilities
- Access Control: By commenting out the code (in app.py, function get_users())
"
    #else:
    #    return render_template("users.html", users=result)
"
users cant see /users/ but they on the other hand can see /users/1, users/2, users/n (so they dont get a list of all users but they can just check each user and see their info)

- Users can access source code: Users write localhost/script.js in the search bar, and access soruce code from the script.js file. This is a big security risk since users should not be able to have access to source code.

- One issue would be if users input a password that is so long that it performs a DOS attack against the server. If the password that an attacker inputs is to long it will take a really long time to hash the password and cause the server to possibly throttle or crash. A way to fix this would be to check if passwords are longer than a certain length and if they are, dont perform hashing on it and display error message on website.

- Alot of the functions use "else" statemnets which by the looks of it returns the same info as the "if" statements. This is not good practise since users seems to get more info than they are suppose to get. There is no point in the "if" statements if the statemnets fails and the "else" statemet returns the same info. Example:

def get_user(userid):
    if userid == 'me':
        u = current_user
    elif (userid == current_user.id):
        u = User.get_user(userid)
    else:
        u = User.get_user(userid)

    if u:
        del u["hash"] # hide hash
        del u["salt"] #hide salt
        if prefers_json():
            return jsonify(u)
        else:
            return render_template("users.html", users=[u])
    else:
        abort(404)

Here we can see that the elif and else statement retrives the same info.

- Other vulnerabiliteis would be urls that are uploaded to the website. Possible fixes would be to check the links that gets uploaded or prevent them form loading or executing the website.

- Regarding passwords, there are no limit in login attempts which means attackers can brute force for passwords using password lists without being rate limited by the website. A fix for this problem would be to limit the amout of attempts a user can try to login to the website. Since there are no login attempt limits, a possible attacker could perform a DOS attack by sending alot of login attempts to the server.

### Threat model
- What is the threat model?
A threat model is a way to identify, communicate and understand threats and mitigations with the context of protecting something of value. In this case the value is the application (web page).

- Who might attack the application?
In the cyber space we could look at threat actors to see who could potentially be actors to target the application. In this case since this application is rather small i doubt the NSA or the russian hackers are going to try to break in to the system (but the 100% could if they wanted to). In reality anyone could be an attacker to this application, but realistic attackers would be people interested in data stored on the webpage, like students, teachers etc or others.

- What can an attacker do?
An attacker could do alot of potentioally harmfull attacks. The attacker would likely start with reconnacanse of the website, before proceeding to start attacks on the vulnerabilites found. An attacker could try phishing attacks at users to try to gain access to user sensitive data, and then futher impersonate that user or go for a DOS attack to Deny avalibility of the server and the application as a whole.

- What damage could be done (in tmers of confidentiality, integrity, availability)?
Confidentiality: Confidential information could be gathered by the attacker by gaining unauthorized access to sensitive user data like password and such.
Integirty: An attacker that gains access to a user could try to impersonate the user and post false and misleading information on the application, which would affect the integrity of the information.
Avalibility: DOS attacks would deny anyone to use the application as the servers would be overloaded or even taken down by the attacker.

- Are there limits to what an attacker can do?
Yes, at the current state of the webpage there are very little harm if the webpage is taken down since there is no acctual use other than very basic features like buddies and such. If we imagine that the platform is at it's full potential there would obviously be more harm that could be done, since more students are using and affected if the service is denied.

- Are there limits to what we can sensibly protect against?
Yes, when it comes to security one has to factor in cost. One could spend the whole school budget to have 24/7 monitoring of the website for malicous activity, but anyone with a reasonable sense would understand that there is no point spending that much money on security. One has to implement security according to how important and neccesarry the service is, and as we explained earlier NSA and Russian hackers are not out threat actors and would be able to gain access to the server if they really wanted to.

- How can you know that your security is good enough (traceability)?
There will always be ways for attackers to gain access to the systems, but there are steps we can take to prevent this as much as we can. The best way to test the security, is by "testing the security"! One could preform pentest ourselves or pay for pentest by other professional companies. In the end there is no way to know if the security is really "good enough".

## Task 2e
# 1 - Implement OIDC
Not done