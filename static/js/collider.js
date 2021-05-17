let config = {}
let child;
let child_flag = false;
let newsys = {  "username": "",
                "sun":{
                  "col": [60, 100, 100],
                  "d": 150 },
                "planets": []};

function preload() {
  // Get the most recent planets
  let url = 'http://3.15.100.29/sketch'; // "http://127.0.0.1:8001/sketch"// //'
  username = getItem("username")
  console.log(username)
  httpPost(url, 'json', {'username': username}).then((data) => {
    config = data
    })
  console.log(config)
}

planets = []
let button;
let err_msg = false;

function setup() {
  createCanvas(windowWidth,windowHeight);
  colorMode(HSB);

  if(!config.sun){
    return
  }
  numPlanets = config.planets.length
  for (let i = 0; i < numPlanets; i++) {
    planetPos = {'x': windowWidth/(numPlanets + 1) * i + 300, 'y':windowHeight/2}
    console.log(config.planets[i].to)
    planets.push( new Planet(config.planets[i].d, planetPos,
                           config.planets[i].from, config.planets[i].to, false,
                           config.planets[i].x1_lines, config.planets[i].y1_lines,
                           config.planets[i].x2_lines, config.planets[i].y2_lines,
                           config.planets[i].x3_lines, config.planets[i].y3_lines,
                           config.planets[i].x4_lines, config.planets[i].y4_lines,
                           config.planets[i].beziers, config.planets[i].angle) )
  }

  button = createButton("Collide");
  button.mouseClicked(collide);
  button.size(100,50);
  button.position(windowWidth - 200, windowHeight - 75)
  button.style("font-family", "Helvetica");
  button.style("font-size", "20px");
}

setuped = false
function draw() {
  if(!config.sun){
    return
  }
  else if(!setuped){
    setup()
    setuped = true
  }
  let c1 = color(236, 68, 1)
  let c2 = color(236, 68, 20)
  //background(236, 68, 10)
  for(let y=0; y<width/2; y++){
    n = map(y,0,width/2,0,1);
    let newc = lerpColor(c1,c2,n);
    stroke(newc);
    line(y,0,y, width);
  }
  for(let y=width/2; y<width; y++){
    n = map(y,width/2,width,0,1);
    let newc = lerpColor(c2,c1,n);
    stroke(newc);
    line(y,0,y, width);
  }

  textSize(24);
  fill(0,0,100)
  textFont('Helvetica')
  text('Select 2 Planets to collide using Genetic Programming!', 30, 100);

  if(err_msg){
    textSize(18);
    fill(0,100,100)
    textFont('Helvetica')
    text('Please select 2 planets', windowWidth-250, 100);
  }

  if (child_flag == false){

    for(let y = 0; y < numPlanets; y++){
      planets[y].create();
    }

  }

  else {
    child.create()
  }

}

function collide(){

   let count = 0
   let parents = []
   for(let y = 0; y < numPlanets; y++){
     if(planets[y].selected){
       count += 1;
       parents.push(planets[y])
     }
     else{
       saveP(planets[y], newsys)
     }
   }
   if(count != 2){
     err_msg = true;
     newsys = {  "username": input.value(),
                     "sun":{
                       "col": [60, 100, 100],
                       "d": 150 },
                     "planets": []};
   }
   else{
     err_msg = false
     let _from = lerpColor(parents[0].from, parents[1].from, random(0, 1))
     let _to = lerpColor(parents[0].to, parents[1].to, random(0, 1))
     let _pos = {'x': windowWidth/2, 'y':windowHeight/2}
     let _from_arr = [hue(_from), saturation(_from), brightness(_from)]
     let _to_arr = [hue(_to), saturation(_to), brightness(_to)]
     child = new Planet(randomGaussian((parents[0].d + parents[1].d)/2, (parents[0].d - parents[1].d)/3),
                            _pos, _from_arr, _to_arr, false,
                            [], [], [], [],[], [], [], [],
                            parents[0].beziers, parents[0].arc_angle);
      child.randomChord();
      child_flag = true;

      button.html("Add to System")
      button.mouseClicked(add2sys)
      button.size(160, 50)

      saveP(child, newsys)

   }
  //   let url = "http://127.0.0.1:8001/"; //'http://3.15.100.29/api';
  //   res = httpPost(url, 'json', config)
  //   window.location.replace('http://127.0.0.1:8080/sys/sys.html');
  // }
}
function add2sys(){
  let url = 'http://3.15.100.29/api'; //"http://127.0.0.1:8001/api"; //
  username = getItem("username")
  newsys.username = username
  res = httpPost(url, 'json', newsys)
  window.location.replace("http://3.15.100.29/sys/sys.html"); //'http://127.0.0.1:8080/sys/sys.html');
}

function saveP(p, newsys){
  let _from_arr = [hue(p.from), saturation(p.from), brightness(p.from)]
  let _to_arr = [hue(p.to), saturation(p.to), brightness(p.to)]
  dict = { "from": _from_arr,
          "to": _to_arr,
          "d": p.d,
          "beziers": p.beziers,
          "angle": p.slice,
          "x1_lines": p.x1_lines,
          "y1_lines": p.y1_lines,
          "x2_lines": p.x2_lines,
          "y2_lines": p.y2_lines,
          "x3_lines": p.x3_lines,
          "y3_lines": p.y3_lines,
          "x4_lines": p.x4_lines,
          "y4_lines": p.y4_lines
  };


  newsys.planets.push(dict)
}


function mouseClicked(){
  for(let y = 0; y < numPlanets; y++){
    d = dist(mouseX, mouseY, planets[y].pos.x, planets[y].pos.y)
    if(d < planets[y].d / 2){
      planets[y].clicked();
    }
  }
}

class Planet {
  constructor(_d, _pos, _from, _to, _ring, _x1, _y1, _x2, _y2, _x3, _y3, _x4, _y4, _bez, _angle) {
    this.mass = _d / 2
    this.pos = _pos
    this.ring = _ring
    this.beziers = _bez
    this.arc_angle = _angle
    this.d = _d

    this.from = color(_from[0], _from[1], _from[2]);
    this.to = color(_to[0], _to[1], _to[2]);
    this.selected = false

    this.x1_lines = _x1;
    this.y1_lines = _y1;
    this.x2_lines = _x2;
    this.y2_lines = _y2;
    this.x3_lines = _x3;
    this.y3_lines = _y3;
    this.x4_lines = _x4;
    this.y4_lines = _y4;
  }

  create() {
    noStroke();
    if(this.selected){
      fill(0,0, 40)
      ellipse(this.pos.x , this.pos.y, this.d + 7)
    }


    fill(this.to)
    ellipse(this.pos.x , this.pos.y, this.d)

    fill(this.from)
    arc(this.pos.x, this.pos.y, this.d, this.d, this.arc_angle, this.arc_angle + PI);

    for(let y = 0; y < this.beziers; y++) {
      let c3 = lerpColor(this.from, this.to, y/this.beziers)
      noStroke()
      fill(c3)
      bezier(this.pos.x + this.x1_lines[y], this.pos.y + this.y1_lines[y],
            this.pos.x + this.x3_lines[y], this.pos.y + this.y3_lines[y],
            this.pos.x + this.x4_lines[y], this.pos.y + this.y4_lines[y],
            this.pos.x + this.x2_lines[y], this.pos.y + this.y2_lines[y]);
     }
  }

  randomChord() {
    // find a random point on a circle
    for(let y = 0; y < this.beziers; y++) {
      // find a random point on a circle
      let angle1 = random(0, 2 * PI);
      this.x1_lines.push(this.d * cos(angle1) * .5);
      this.y1_lines.push(this.d * sin(angle1) * .5);

      // find another random point on the circle
      let angle2 = random(0, 2 * PI);
      this.x2_lines.push(this.d * cos(angle2) * .5);
      this.y2_lines.push(this.d * sin(angle2) * .5);

      this.x3_lines.push(this.d * cos(angle2 - PI * random(2)) * .5);
      this.y3_lines.push(this.d * sin(angle2 - PI * random(2)) * .5);

      this.x4_lines.push(this.d * cos(angle2 + PI * random(2)) * .5);
      this.y4_lines.push(this.d * sin(angle2 + PI * random(2)) * .5);

    }
  }

  clicked(){
    if(this.selected) this.selected = false;
    else this.selected = true;
  }

}
