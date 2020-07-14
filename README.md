# Spam-Detection

# Malicious URL Detection
## Install Dependencies:
**pip3:** Python package manager  
**sklearn:**  In python, sklearn is a machine learning package which includes various ML algorithms.  
**numpy:**  It is a numeric python module which provides efficient math functions for calculations.

## Instructions for Ubuntu 18.04
### Install pip3
#### 1. Start by updating the package list using the following command:

#### 2. Use the following command to install pip for Python 3:  
`$ sudo apt install python3-pip`  
The command above will also install all the dependencies required for building Python modules.

#### 3. Once the installation is complete, verify the installation by checking the pip version:  
`$ pip3 --version`  
The version number may vary, but it will look something like this:  
`$ pip 9.0.1 from /usr/lib/python3/dist-packages (python 3.6)`  
### Install scikit-learn(sklearn)
`$ pip3 install -U scikit-learn`  

### Install numpy
`$ pip3 install numpy`  

## Usage:
### Convert data sets from .arff to .csv files
`$ python3 arffcsv.py <input.arff> <output.csv>`  
**NOTE:** If output file isn't specified, the file saves under input file name with .csv file tag

### Program can be ran with command:
`$ python3 url_detection.py <input.csv>`

The program will read the provided data set and split it into 80% training and 20% testing data. Program runs data set through logistic regression and decision tree classifier. After completion the program writes results to results.txt

## Example
![Alt text](./example_usage.png?raw=true "Optional Title")  

UCIDataset1.csv  
Number of Instances: 1353  

| Algorithm           | Accuracy          | Precision         | Recall            | F1-Score          |
|:-------------------:|:-----------------:|:-----------------:|:-----------------:|:-----------------:|
| Logistic Regression | 83.27171903881701 | 81.45928965017765 | 83.27171903881701 | 82.35553384679035 |
| Decision Tree       | 85.58225508317929 | 85.95692205554467 | 85.58225508317929 | 85.7691794052791  |

UCIDataset2.csv  
Number of Instances: 11055  

| Algorithm           | Accuracy           | Precision         | Recall            | F1-Score          |
|:-------------------:|:------------------:|:-----------------:|:-----------------:|:-----------------:|
| Logistic Regression | 84.45273631840796  | 85.47781132505413 | 84.45273631840796 | 84.96218203280957 |
| Decision Tree       | 90.63772048846675  | 90.86780223492148 | 90.63772048846675 | 90.75261553249493 |

# Data set References:
(UCIDatasets 1 & 2)
Dua, D. and Graff, C. (2019). UCI Machine Learning Repository [http://archive.ics.uci.edu/ml]. Irvine, CA: University of California, School of Information and Computer Science.  

### Attempted URL feature extraction program
The mailparser.py program was an attempt to extract URLs from a directory of individual .eml email files in order to create our own dataset for training. This program was abandoned due to the lack of actual phishing emails in the email accounts we had access to.

Program can be run with the command:
```
python3 mailparser.py <input_folder> <output_file> <suspicious>
E.g.:   mailparser.py sample/spam    spam.csv      True
```
The features of the URLs found inside the emails in input_folder will be appended in CSV format to output_file and tagged as either suspicious or not. We intended the data produced by this to later be imported into url_detection.py as the main dataset but used an alternate dataset instead with somewhat different features instead.
