let config = {}

// const start = async function() {
//   const response = await fetch('https://ashwinpo.github.io/solarsys/sys/config.json');
//   config = await response.json();
//   console.log(config);
// }

function preload() {
  // Get the most recent earthquake in the database
  let url = 'http://3.15.100.29/api';
   //'https://ashwinpo.github.io/solarsys/sys/config.json';
  config = loadJSON(url);
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
  sun = new Body(config.sun.mass,createVector(0,0),createVector(0,0),
    [10,20,30], [40,50,60], false, [], [], [], [], [], [], [], [], 0)
  numPlanets = config.planets.length
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
    planets.push( new Body(config.planets[i].d, planetPos, planetVel,
                           config.planets[i].from, config.planets[i].to, false,
                           config.planets[i].x1_lines, config.planets[i].y1_lines,
                           config.planets[i].x2_lines, config.planets[i].y2_lines,
                           config.planets[i].x3_lines, config.planets[i].y3_lines,
                           config.planets[i].x4_lines, config.planets[i].y4_lines, config.planets[i].beziers) )
    planets[i].randomChord()
  }

  for(let i = 0;i<width/10;i++){
    particles.push(new Particle());
  }
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



function Body(_d, _pos, _vel, _from, _to, _ring, _x1, _y1, _x2, _y2, _x3, _y3, _x4, _y4, _bez){
  this.mass = _d / 2
  this.pos = _pos
  this.vel = _vel
  this.d = _d
  this.thetaInit = 0
  this.path = []
  this.pathLen = 10
  this.from = color(_from[0], _from[1], _from[2]);
  this.to = color(_to[0], _to[1], _to[2]);
  this.beziers = 2

  this.x1_lines = _x1;
  this.y1_lines = _y1;
  this.x2_lines = _x2;
  this.y2_lines = _y2;
  this.x3_lines = _x3;
  this.y3_lines = _y3;
  this.x4_lines = _x4;
  this.y4_lines = _y4;

  this.line_col = [0,0,255]
  this.ring = _ring
  this.ringAngle = random(-5,5)

  this.arc_angle = PI * random(1, 2)
  this.show = function() {
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
      bezier(this.pos.x + this.x1_lines[y], this.pos.y + this.y1_lines[y],
            this.pos.x + this.x3_lines[y], this.pos.y + this.y3_lines[y],
            this.pos.x + this.x4_lines[y], this.pos.y + this.y4_lines[y],
            this.pos.x + this.x2_lines[y], this.pos.y + this.y2_lines[y]);
     }
  }

  this.randomChord = function() {

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


  this.move = function() {
    this.pos.x += this.vel.x
    this.pos.y += this.vel.y
    this.path.push(createVector(this.pos.x,this.pos.y))
    if (this.path.length > 100) this.path.splice(0,1)
  }

  this.applyForce = function(f) {
    this.vel.x += f.x / this.mass
    this.vel.y += f.y / this.mass
  }

  this.attract = function(child) {
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
