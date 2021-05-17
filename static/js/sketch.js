let config = {}

function preload() {
  // Get the most recent planets
  let url = 'http://3.15.100.29/sketch'; //' "http://127.0.0.1:8001/sketch"
  username = getItem("username")
  console.log(username)
  httpPost(url, 'json', {'username': username}).then((data) => {
    config = data
    })
  console.log(config)
}


let planets = []
let sun
let numPlanets = 0
let G = 120
let destabilise = 0.15
let particles = [];


function setup() {
  createCanvas(windowWidth,windowHeight)
  colorMode(HSB)
  if(!config.sun){
    return
  }
  sun = new Sun(config.sun.d, config.sun.col)
  numPlanets = config.planets.length
  console.log(config)
    // Initialise the planets
  for (let i = 0; i < numPlanets; i++) {
    let mass = config.planets[i].d/2
    let radius = random(sun.d, min(windowWidth/2,windowHeight/2))
    let angle = random(0, TWO_PI)
    let planetPos = createVector(radius * cos(angle), radius * sin(angle))

    // Find direction of orbit and set velocity
    let planetVel = planetPos.copy()
    if (random(1) < 0.1) planetVel.rotate(-HALF_PI)
    else planetVel.rotate(HALF_PI)  // Direction of orbit
    planetVel.normalize()
    planetVel.mult( sqrt((G * sun.mass)/(radius)) ) // Circular orbit velocity
    planetVel.mult( random( 1-destabilise, 1+destabilise) ) // create elliptical orbit
    planets.push( new Planet(config.planets[i].d, planetPos, planetVel,
                           config.planets[i].from, config.planets[i].to, false,
                           config.planets[i].x1_lines, config.planets[i].y1_lines,
                           config.planets[i].x2_lines, config.planets[i].y2_lines,
                           config.planets[i].x3_lines, config.planets[i].y3_lines,
                           config.planets[i].x4_lines, config.planets[i].y4_lines,
                           config.planets[i].beziers, config.planets[i].angle) )
  }

  for(let i = 0;i<width/10;i++){
    particles.push(new Particle());
  }
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
  // Gradient Background
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

  for(let i = 0;i<particles.length;i++) {
    particles[i].createParticle();
    particles[i].moveParticle();
    //particles[i].joinParticles(particles.slice(i));
  }
  translate(width/2, height/2)
  for (let i = numPlanets-1; i >= 0; i--) {
    sun.attract(planets[i])
    planets[i].move()
    planets[i].show()
  }
  sun.show()



}

let dim = .55

class Planet{
  constructor(_d, _pos, _vel, _from, _to, _ring, _x1, _y1, _x2, _y2, _x3, _y3, _x4, _y4, _bez, _angle){
    this.mass = _d / 2
    this.pos = _pos
    this.vel = _vel
    this.d = _d * dim
    this.ring = _ring
    this.beziers = _bez
    this.arc_angle = _angle

    this.path = []
    this.pathLen = 10
    this.line_col = [0,0,255]
    this.from = color(_from[0], _from[1], _from[2]);
    this.to = color(_to[0], _to[1], _to[2]);

    this.x1_lines = _x1;
    this.y1_lines = _y1;
    this.x2_lines = _x2;
    this.y2_lines = _y2;
    this.x3_lines = _x3;
    this.y3_lines = _y3;
    this.x4_lines = _x4;
    this.y4_lines = _y4;

  }

  show(){
    stroke(this.line_col[0], this.line_col[1], this.line_col[2])
    for (let i = 0; i < this.path.length-2; i++) {
      line(this.path[i].x, this.path[i].y, this.path[i+1].x, this.path[i+1].y,)
    }
    if(this.ring == true){
      stroke(255);
      noFill()
      //rotate(this.ringAngle);
      ellipse(this.pos.x, this.pos.y, (this.d * 3), (this.d * 0.8))
    }

    fill(this.to); noStroke()
    ellipse(this.pos.x, this.pos.y, this.d, this.d)
    fill(this.from)
    arc(this.pos.x, this.pos.y, this.d, this.d, this.arc_angle, this.arc_angle + PI);

    for(let y = 0; y < this.beziers; y++) {
      let c3 = lerpColor(this.from, this.to, y/this.beziers)
      noStroke()
      fill(c3)
      bezier(this.pos.x + this.x1_lines[y] * dim, this.pos.y + this.y1_lines[y] * dim,
            this.pos.x + this.x3_lines[y] * dim, this.pos.y + this.y3_lines[y] * dim,
            this.pos.x + this.x4_lines[y] * dim, this.pos.y + this.y4_lines[y] * dim,
            this.pos.x + this.x2_lines[y] * dim, this.pos.y + this.y2_lines[y] * dim);
     }
  }

  move() {
    this.pos.x += this.vel.x
    this.pos.y += this.vel.y
    this.path.push(createVector(this.pos.x,this.pos.y))
    if (this.path.length > 100) this.path.splice(0,1)
  }

  applyForce(f) {
    this.vel.x += f.x / this.mass
    this.vel.y += f.y / this.mass
  }

  // attract(child) {
  //   let r = dist(this.pos.x, this.pos.y, child.pos.x, child.pos.y)
  //   let f = (this.pos.copy()).sub(child.pos)
  //   f.setMag( (G * this.mass * child.mass)/(r * r) )
  //   child.applyForce(f)
  // }

}

class Sun{

  constructor(_d, _col){
    this.mass = _d / 2
    this.pos = createVector(0,0)
    this.d = _d
    this.col = color(_col[0], _col[1], _col[2])
  }

  show(){
    fill(this.col); noStroke()
    ellipse(this.pos.x, this.pos.y, this.d, this.d)
  }

  attract(child) {
    let r = dist(this.pos.x, this.pos.y, child.pos.x, child.pos.y)
    let f = (this.pos.copy()).sub(child.pos)
    f.setMag( (G * this.mass * child.mass)/(r * r) )
    child.applyForce(f)
  }
}



// this class describes the properties of a single particle.
class Particle {
// setting the co-ordinates, radius and the
// speed of a particle in both the co-ordinates axes.
  constructor(){
    this.x = random(-windowWidth,windowWidth);
    this.y = random(-windowHeight,windowHeight);
    this.r = random(1,8);
    this.brightness = random(0,100)

    if(random(0,1) < 0.5){
      this.xSpeed = -.05
      this.ySpeed = random(-.05,.05);
    }
    else{
      this.xSpeed = .05
      this.ySpeed = random(-.05,.05);
    }


  }

// creation of a particle.
  createParticle() {
    noStroke();
    fill(0,0,this.brightness + random(-1,1));
    circle(this.x,this.y,this.r);
  }

// setting the particle in motion.
  moveParticle() {
    if(this.x < 0 || this.x > width)
      this.xSpeed*=-1;
    if(this.y < 0 || this.y > height)
      this.ySpeed*=-1;
    this.x+=this.xSpeed;
    this.y+=this.ySpeed;
  }

// this function creates the connections(lines)
// between particles which are less than a certain distance apart
  joinParticles(particles) {
    particles.forEach(element =>{
      let dis = dist(this.x,this.y,element.x,element.y);
      if(dis<85) {
        stroke('rgba(255,255,255,0.04)');
        line(this.x,this.y,element.x,element.y);
      }
    });
  }
}
