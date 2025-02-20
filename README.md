# LBS-HE Project

## Info
lbs_project.js simulates privacy-preserving distance calculations using homomorphic encryption.

Through X iterations, random geodetic coordinates are generated for two clients. These are then encrypted and the Euclidean distance between them are computed while encrypted.
The computed distance and the execution time are then stored in a CSV file in the root folder - along with various baselines.

## Dependencies
- [GeographicLib](https://www.npmjs.com/package/geographiclib)
- [node-seal](https://github.com/s0l0ist/node-seal) (must be installed manually)

## Installation
Clone repo and run "npm install"