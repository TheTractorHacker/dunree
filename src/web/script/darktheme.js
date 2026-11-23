/*
    Dark Theme Toggle Manager

    This script is used to manage the dark theme toggle button in the header of the website.
    It will change the theme of the website to dark mode when the toggle is clicked and back to light mode when clicked again.

    Must be included just after the start of body tag in the HTML file.
    The choice is stored through script/safestorage.js (zxStore), loaded before this file: when the browser blocks
    storage the choice is kept in memory, so the toggle still works until the page is reloaded.
*/

//Plugin pages and older copies of a page may load this file without safestorage.js: guarded direct calls then
var _themeStore = window.zxStore || {
    get: function(k){ try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function(k, v){ try { localStorage.setItem(k, v); } catch (e) {} },
    remove: function(k){ try { localStorage.removeItem(k); } catch (e) {} }
};

//The top bar (script/topbar.js) listens to this to show the current mode
function _themeChanged(){
    try { document.dispatchEvent(new CustomEvent("zoraxy:theme")); } catch (e) {}
}

function _whiteThemeHandleApplyChange(){
    $(".menubar .logo").attr("src", "img/logo.svg");
}

function _darkThemeHandleApplyChange(){
    $(".menubar .logo").attr("src", "img/logo_white.svg");
}


 //Check if the theme is dark, must be done before the body is loaded to prevent flickering
 function setDarkTheme(isDarkTheme = false){
    if (isDarkTheme){
        $("body").addClass("darkTheme");
        _themeStore.set("theme", "dark");
        _themeChanged();

        //Check if the page is still loading, if not change the logo
        if (document.readyState == "complete"){
            _darkThemeHandleApplyChange();
        }else{
            //Wait for the page to load and then change the logo
            $(document).ready(function(){
                _darkThemeHandleApplyChange();
            });
        }
    }else{
        $("body").removeClass("darkTheme")
        _themeStore.set("theme", "light");
        _themeChanged();
        //By default the page is white theme. So no need to change the logo if page is still loading
        if (document.readyState == "complete"){
            //Switching back to light theme
            _whiteThemeHandleApplyChange();
        }
    }
}

//No stored choice yet: follow the operating system preference ("auto") until the user picks a theme
function _systemPrefersDark(){
    try {
        return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    } catch (e) {
        return false;
    }
}

var _storedTheme = _themeStore.get("theme");
if (_storedTheme == "dark"){
    setDarkTheme(true);
}else if (_storedTheme == null && _systemPrefersDark()){
    setDarkTheme(true);
    _themeStore.remove("theme"); //keep "auto" until the user toggles
}else{
    setDarkTheme(false);
    if (_storedTheme == null){
        _themeStore.remove("theme");
    }
}
