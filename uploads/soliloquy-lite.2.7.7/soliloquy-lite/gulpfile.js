const gulp = require('gulp');
const plugins = require('gulp-load-plugins')();
const run = require('gulp-run-command').default;
/**
 * Helper method to load task.
 *
 * @since 1.0.0
 *
 * @param {*} task  Task to Load.
 */
function getTask(task) {
	return require('./_tasks/' + task)(gulp, plugins);
}

const scripts = getTask('scripts');
const styles = getTask('styles');
const soliloquy = getTask('soliloquy_js');

gulp.task('scripts', scripts);
gulp.task('styles', styles);
gulp.task('soliloquy', soliloquy);

gulp.task('build', gulp.parallel(soliloquy, scripts, styles));

gulp.task('watch', function () {
	gulp.watch('assets/js/*.js', scripts);
	gulp.watch('assets/scss/*.scss', styles);
});

gulp.task('plugins', function () {
	return new Promise(function (resolve, reject) {
		console.log('gulp plugins');
		console.log(plugins);
		resolve();
	});
});
