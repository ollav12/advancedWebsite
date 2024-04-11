import {render, html } from '/uhtml.js';

/**
 * Wrapper around fetch() for JSON data
 * 
 * @param {*} path The path (or URL)
 * @param {*} method Request method, defaults to GET
 * @param {*} headers Additional headers
 * @returns The response data, as an object, or null if the request failed
 */
export async function fetch_json(path, method='GET', headers = {}) {
    const resp = await fetch(path, {
        method, 
        headers:{
            accept: 'application/json',
            ...headers
        }});
    if(resp.ok) {
        return await resp.json();
    } else {
        console.error('Request failed:', resp.status, resp.statusText);
        return null;
    }
}

/**
 * Get list of users from server
 * 
 * @returns A list of simple user objects (only id and username)
 */
export async function list_users() {
    return await fetch_json('/users') || [];
}

/**
 * Get a user profile from the server
 * @param {*} userid The numeric user id
 * @returns A user object
 */
export async function get_profile(userid) {
    return await fetch_json(`/users/${userid}`);
}

/**
 * Format a key-value field
 * 
 * @param {*} key The key
 * @param {*} value The value
 * @param {*} options Object with options {optional: bool, className: string, long: bool}
 * @returns HTML text
 */
export function format_field(key, value, options = {}) {
    if(options.optional && !value)
        return '';
    let classNames = 'field';
    if(options.className) // if we need extra styling
        classNames = `${classNames} ${options.className}`;
    if(options.long) // if the value is a longer text
        classNames = `${classNames} long`;
    const val = options.long ? `<div class="value">${value || ''}</div>` : ` <span class="value">${value || ''}</span>`
    return `<li class="${classNames}"><span class="key">${key}</span>${val}</li>`
}

/**
 * Display a user as a HTML element
 * 
 * @param {*} user A user object
 * @param {*} elt An optional element to render the user into
 * @returns elt or a new element
 */
export function format_profile(user, elt) {
    if(!elt) 
        elt = document.createElement('div');
    elt.classList.add('user'); // set CSS class
    if(user.id == current_user_id) { // current_user_id is a global variable (set on 'window')
        elt.classList.add('me');
    }
    // This is now safe since we sanitize user input
    user.color = sanitizeUserInput(user.color);
    user.about = sanitizeUserInput(user.about);

    elt.innerHTML = `
        <img src="${user.picture_url || '/unknown.png'}" alt="${user.username + "'s profile picture"}">
        <div class="data">
            ${format_field('Name', user.username)}
            <div class="more">
                ${format_field('Birth date', user.birthdate)}
                ${format_field('Favourite colour', `${user.color} <div class="color-sample" style="${'background:'+user.color}"></div>`)}
                ${format_field('About', user.about, 'long')}
            </div>
        </div>
        <div class="controls">
            ${window.current_user_id == user.id ? '' : `<button type="button" data-user-id="${user.id}" data-action="add_buddy">Add buddy</button>`}
        </div>
    `;
    
    return elt;
}

// This function is used to sanitize the input from the user
export function sanitizeUserInput(input) {
    if (typeof input === 'undefined') {
        console.log('Input is undefined');
        return null
    }
    // Use a regular expression to remove all HTML tags
    return input.replace(/<[^>]*>/g, '');
}
   


/**
 * Perform an action, such as a button click.
 * 
 * Get the action to perform and any arguments from the 'data-*' attributes on the button element.
 * 
 * @param {*} element A button element with `data-action="…"` set
 * @returns true if action was performed
 */
export async function do_action(element) {
    if(element.dataset.action === 'add_buddy') {
        result = await fetch_json(`/buddies/${element.dataset.userId}`, 'POST')
        console.log(result);
        return true;
    }
    return false;
}














// demo of uhtml templates
function uhtml_demo() {
    const main = document.querySelector('main');
    function show_demo(name, template) {
        console.log(name, simple_tmpl);
        const elt = document.createElement('div');
        main.appendChild(elt);
        render(elt, html`<h3>${name}</h3>${template}`);
    }
    const unsafe_data = '<script>alert()</script>'
    // safely inserted as a string
    const simple_tmpl =  html`<em>${unsafe_data}</em>`; 
    show_demo('simple_tmpl', simple_tmpl);

    const username = "foo", nested = "nested";
    const user = html`<em>${username}</em>`
    // nested templates are inserted as HTML elements
    const message_tmpl = html`<div>Hello, my name is ${user}, and your name is ${html`<b>${nested}</b>`}</div>`
    show_demo('message_tmpl', message_tmpl)

    const users = ['alice', 'bob']
    // you can also use lists
    const users_tmpl = html`<ul>${users.map(user => html`<li>${user}</li>`)}</ul>`
    show_demo('users_tmpl', users_tmpl);

    const color = "red";
    // attributes require special care
    const attr_tmpl = html`<div class="color-sample" style="${'background:' + color}">`;
    show_demo('attr_tmpl', attr_tmpl)

    // this won't work
    const attr_tmpl_err = html`<div class="color-sample" style="background: ${color}">`;
    try {
        show_demo('attr_tmpl_err', attr_tmpl_err)
    } catch(e) {
        console.error(e);
    }

}

window.uhtml_demo = uhtml_demo;

function createElement_demo() {
    function element(tag, {cssClass, child}={}) {
        const elt = document.createElement(tag);
        if(cssClass)
            elt.className = cssClass;
        if (typeof child === 'string' || typeof child === 'number')
            elt.innerText = `${child}`;
        else if (child)
            elt.appendChild(text);
        return elt;
    }

    const fields = [{key:'Name', value:'alice'}, {key:'Favourite color', value:'pink'}]
    const outerDiv = element('div', {cssClass:'data'});
    fields.forEach(field => {
        const item = element('li', {cssClass:'field'});
        item.appendChild(element('span', {cssClass:'key', child:field.key}))
        item.appendChild(element('span', {cssClass:'value', child:field.value}))
        outerDiv.appendChild(item)
    })
    document.querySelector('main').appendChild(element('h3', {child:'createElement demo'}))
    document.querySelector('main').appendChild(outerDiv);
}
window.createElement_demo = createElement_demo;
