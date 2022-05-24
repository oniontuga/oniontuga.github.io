var ctx, canvas;
url = new URL(window.location)
if (url.searchParams.get("image") == null) {
    url.searchParams.set("image", "2")
    window.history.pushState({},"",url)
}

function retrieveImage() {
    $('.spinner-box').show();
    $('img').css("filter", "brightness(50%)");
    $.ajax({
        url: "../assets/img/gallery/" + url.searchParams.get("image") + ".txt", 
        success: function(data, status) {
            canvas = document.createElement("canvas");
            ctx = canvas.getContext('2d');
            response = data.split("\n");
            resolution = response[0].split(",")
            canvas.width = parseInt(resolution[0]);
            canvas.height = parseInt(resolution[1]);
            decryptAES(response[1]);
        },
        complete: function() {
            $('.spinner-box').hide();
        }
    });
}

retrieveImage();

function canvasStringToArr(s) {
    var p=[];
    for (var i=0; i<s.length; i+=3) {
      for (var j=0; j<3; j++) {
        p.push(s.substring(i+j,i+j+1).charCodeAt());
      } 
      p.push(255);
    }
    return p;
}

function decryptAES(s) {
    var password = sessionStorage.getItem("galleryAuthenticator");
    try {
        var arr=canvasStringToArr(Krypto.AES.decrypt(s, password));
        imgd = ctx.createImageData(canvas.width,canvas.height);
        for (var i=0; i<arr.length; i++) { imgd.data[i]=arr[i]; }
        ctx.putImageData(imgd, 0, 0);
        var carousel = document.getElementById("carousel");
        var img = document.createElement("img");
        img.src = canvas.toDataURL("image/png");
        img.classList.add("carousel__photo");
        img.classList.add("initial");
        for (var i = 0; i < carousel.children.length; i++) {
            if (carousel.children[i].classList.contains("initial")) {
                carousel.removeChild(carousel.children[i])
                break;
            }
        }
        carousel.appendChild(img);
    } catch (error) {
        //window.location.replace("/login");
    }
}

function nextImage() {
    pageNumber = parseInt(url.searchParams.get("image")) + 1
    url.searchParams.set("image", pageNumber.toString())
    window.history.pushState({},"",url)
    retrieveImage();
}

function previousImage() {
    pageNumber = parseInt(url.searchParams.get("image")) - 1
    url.searchParams.set("image", pageNumber.toString())
    window.history.pushState({},"",url)
    retrieveImage();
}

$(window).on('popstate', function(event) {
    url = new URL(window.location.href)
    retrieveImage();
});
