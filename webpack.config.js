var nodeExternals = require('webpack-node-externals')

module.exports = {
	// Specify the entry point for our app
	entry: [
		'./src/index.js'
	],

	// Specify the output file containing our bundled code
	output: {
		filename: 'index.js',
		library: "index",
		libraryTarget: 'commonjs2'
	},

	// Let webpack know to generate a Node.js bundle
	target: "node",

	// Only dependencies listed in our package.json file will be bundled.
	// This allows us to filter out stock lambda packages like AWS.
	// So anything in the lambda environment only put in devdependencies.
	externals: [nodeExternals({
		modulesFromFile: {
			exclude: ['dependencies']
		}
	})]
}
