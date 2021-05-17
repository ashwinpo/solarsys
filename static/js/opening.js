
planets = []
let button;
let err_msg = false;

function setup() {
  createCanvas(windowWidth,windowHeight);
  colorMode(HSB);

  for(let y = 1; y < 6; y++){

    p = new Planet(windowWidth/6 * y - 20, windowHeight/2);
    p.randomChord();
    planets.push(p);
  }

  button = createButton("Continue");
  button.mouseClicked(cont);
  button.size(100,50);
  button.position(windowWidth - 200, windowHeight - 75)
  button.style("font-family", "Helvetica");
  button.style("font-size", "20px");

}

function draw() {
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
  text('Select 3 Planets for your System', 30, 100);


  if(err_msg){
    textSize(18);
    fill(0,100,100)
    textFont('Helvetica')
    text('Please select 3 planets', windowWidth-250, 100);
  }



  for(let y = 0; y < 5; y++){
    planets[y].create();
  }




}

function cont(){
  let count = 0
  let config = {  "sun":{
                    "col": [60, 100, 100],
                    "d": 150 },
                  "planets": []};
  for(let y = 0; y < 5; y++){
    if(planets[y].selected){
      count += 1;
      saveP(planets[y], config)
    }
  }
  if(count != 3){
    err_msg = true;
  }
  else{
    err_msg = false;
    let url = "http://127.0.0.1:5000/save";
    res = httpPost(url, 'json', config)
    console.log(res)
    window.location.replace('http://127.0.0.1:5000/sys_frame'); //'http://127.0.0.1:8080/sys/sys.html'
 }
}

function saveP(p, config){
  dict = { "from": p.from_arr,
          "to": p.to_arr,
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


  config.planets.push(dict)
}

function mouseClicked(){
  for(let y = 0; y < 5; y++){
    d = dist(mouseX, mouseY, planets[y].pos.x, planets[y].pos.y)
    if(d < planets[y].d / 2){
      planets[y].clicked();
    }
  }
}

class Planet {
  constructor(x, y) {
    this.from_arr = [random(0, 360), random(50, 100), random(30, 100)]
    this.from = color(this.from_arr[0], this.from_arr[1], this.from_arr[2]);
    this.to_arr = [random(0, 360), random(50, 100), random(10, 30)];
    this.to = color(this.to_arr[0], this.to_arr[1], this.to_arr[2]);
    this.c1 = lerpColor(this.from, this.to, 0.33);
    this.c2 = lerpColor(this.from, this.to, 0.66);
    this.pos = {'x': x, 'y': y}
    this.d = random(40, 155)
    this.beziers = 2
    this.slice = PI * random(1, 2)
    this.selected = false
    this.mass = random(10, 100)

    this.x1_lines = [];
    this.x2_lines = [];
    this.y1_lines = [];
    this.y2_lines = [];
    this.x3_lines = [];
    this.x4_lines = [];
    this.y3_lines = [];
    this.y4_lines = [];
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
    arc(this.pos.x, this.pos.y, this.d, this.d, this.slice, this.slice + PI);

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

  clicked(){
    if(this.selected) this.selected = false;
    else this.selected = true;
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
}
