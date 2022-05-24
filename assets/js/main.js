var lazyLoadInstance = new LazyLoad({
    elements_selector: ".lazy"
});
lazyLoadInstance.update();

var pagename = window.location.pathname.replaceAll('/', '');

var descendents = document.getElementById('links').getElementsByTagName('div');

var i, e, d;
for (i = 0; i < descendents.length; ++i) {
    if (descendents[i].id == pagename) {
        descendents[i].style.fontWeight = "bold"
    } else {
        descendents[i].style.fontWeight = "normal"
    }
    
}


