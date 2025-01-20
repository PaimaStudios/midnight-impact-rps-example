const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const webpack = require('webpack');
const WasmPackPlugin = require("@wasm-tool/wasm-pack-plugin");

module.exports = {
  entry: './index.ts',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'index.js',
  },
  plugins: [
    new HtmlWebpackPlugin(),
    // new WasmPackPlugin({
    //     crateDirectory: path.resolve(__dirname, ".")
    // }),
  ],
  mode: 'development',
  experiments: {
    asyncWebAssembly: true
  },
  devServer: {
    headers: [
      {
        key: 'Cross-Origin-Embedder-Policy',
        value: 'require-corp',
      },
      {
        key: 'Cross-Origin-Opener-Policy',
        value: 'same-origin',
      },
    ],
  },
  resolve: {
    extensions: ['.ts', '.js'],
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
};
