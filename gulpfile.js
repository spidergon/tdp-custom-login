'use strict'

const { series, src, dest, watch } = require('gulp')
const del = require('del')
const vinylPaths = require('vinyl-paths')
const imagemin = require('gulp-imagemin')
const sourcemaps = require('gulp-sourcemaps')
const sass = require('gulp-sass')
const postcss = require('gulp-postcss')
const notify = require('gulp-notify')
const plumber = require('gulp-plumber')
const gulpif = require('gulp-if')
const zip = require('gulp-zip')
const cache = require('gulp-cache')

let isProd = false

const dir = {
  root: './',
  src: './src/',
  build: './build/'
}

const dist = {
  name: 'build.zip',
  build: dir.build + './dist/',
  src: [
    // include common file types
    '**/*.php',
    '**/*.html',
    '**/*.css',
    '**/*.js',
    '**/*.svg',
    '**/*.ttf',
    '**/*.otf',
    '**/*.eot',
    '**/*.woff',
    '**/*.woff2',
    '**/*.scss',
    '**/*.json',
    // include specific files and folders
    'screenshot.png',
    '.eslintrc',
    '.gitignore',
    '**/images/**/*',
    '**/languages/**/*',
    // exclude files and folders
    '!.git/**/*',
    '!node_modules/**/*'
  ],
  srcOptions: { dot: true }
}

const imgSettings = {
  src: dir.src + 'img/**/*',
  build: dir.root + 'images/'
}

const cssSettings = {
  src: dir.src + 'styles/style.scss',
  watch: dir.src + 'styles/**/*',
  build: dir.root, // css file on root (WordPress)
  sassOpts: {
    outputStyle: 'nested',
    imagePath: images.build,
    precision: 3,
    errLogToConsole: true
  },
  processors: [
    require('postcss-assets')({
      loadPaths: ['images/'],
      basePath: dir.root,
      baseUrl: isProd ? dir.root : '/lingroove/wp-content/plugins/tdp-sound/'
    }),
    require('autoprefixer')({
      browsers: ['last 2 versions', '> 2%']
    }),
    require('css-mqpacker'),
    require('cssnano')
  ]
}

const notifier = notify.withReporter((options, callback) => callback())

async function clean () {
  await src([`${dir.root}style.css`, `${dir.build}*.zip`], { allowEmpty: true })
    .pipe(vinylPaths(del))
    .pipe(notify({ message: 'Build files removed', onLast: true }))
  await src(imgSettings.build, { allowEmpty: true })
    .pipe(vinylPaths(del))
    .pipe(notifier('Images folder removed'))
  cache.clearAll()
}

function images () {
  return src(imgSettings.src)
    .pipe(
      imagemin([
        imagemin.gifsicle({ interlaced: true }),
        imagemin.jpegtran({ progressive: true }),
        imagemin.optipng({
          optimizationLevel: 7,
          progressive: true,
          interlaced: true
        }),
        imagemin.svgo({
          plugins: [
            {
              removeViewBox: false,
              collapseGroups: true
            }
          ]
        })
      ])
    )
    .pipe(dest(imgSettings.build))
}

function css () {
  return src(cssSettings.src)
    .pipe(plumber())
    .pipe(gulpif(!isProd, sourcemaps.init()))
    .pipe(sass(cssSettings.sassOpts))
    .pipe(postcss(cssSettings.processors))
    .pipe(gulpif(!isProd, sourcemaps.write()))
    .pipe(dest(cssSettings.build))
}

function setProd (done) {
  isProd = true
  done()
}

function buildFiles () {
  return src(dist.src, dist.srcOptions)
    .pipe(dest(dist.build))
    .pipe(notify({ message: 'Copy from buildFiles complete', onLast: true }))
}

function buildZip () {
  return src(dist.build + '**', dist.srcOptions)
    .pipe(zip(dist.name))
    .pipe(dest(dir.build))
    .pipe(notify({ message: 'Zip task complete', onLast: true }))
}

function cleanBuild () {
  return src(dist.build)
    .pipe(vinylPaths(del))
    .pipe(notifier('Build folder removed'))
}

function watchFiles () {
  console.log('*** Watching files... ***')
  const watchSettings = { ignoreInitial: false }
  watch(imgSettings.src, watchSettings, images)
  watch(cssSettings.watch, watchSettings, css)
}

exports.clean = clean
exports.images = images
exports.css = series(images, css)
exports.watch = series(images, watchFiles)
exports.build = series(
  setProd,
  clean,
  images,
  css,
  buildFiles,
  buildZip,
  cleanBuild
)
exports.default = series(clean, images, watchFiles)
