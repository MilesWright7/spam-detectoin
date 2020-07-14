#!/usr/bin/env python3
#sklearn forces depreciation warning - hide them
def warn(*args, **kwargs):
    pass
import warnings
warnings.warn = warn

#... import sklearn stuff...
import numpy as np
from sklearn import *
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
import sys

RESULTFILE = "results.txt"
# Adjust percentage of data set for training
SPLIT = 0.2

def evaluate (outputs, pred, file):
    accuracy = 100.0 * accuracy_score(outputs, pred)
    precision = 100.0 * precision_score(outputs, pred, average = 'weighted')
    recall = 100.0 * recall_score(outputs, pred, average = 'weighted')
    file.write("--------------------------------Results--------------------------------\n")
    file.write("The accuracy testing data is: " + str(accuracy) + "\n")
    file.write("The precision testing data is: " + str(precision) + "\n")
    file.write("The recall testing data is: " + str(recall) + "\n")
    file.write("The F1-Score testing data is: " + str(2.0*(recall*precision)/(recall+precision)) + "\n\n")

def main():

    if len(sys.argv) is not 2:
        print("usage: url_detection.py <input.csv>")
        sys.exit()

    fw = open(RESULTFILE, "w")

    training_data = np.genfromtxt(str(sys.argv[1]), delimiter=',', dtype=np.int32)

    split_size = round(len(training_data) * SPLIT)
 
    inputs = training_data[:,:-1]
    outputs = training_data[:, -1]

    training_inputs = inputs[:split_size]
    training_outputs = outputs[:split_size]
    testing_inputs = inputs[split_size:]
    testing_outputs = outputs[split_size:]

    classifier = LogisticRegression(solver = 'lbfgs')
    classifier.fit(training_inputs, training_outputs)
    predictions = classifier.predict(testing_inputs)

    fw.write("Evaluating Logistic Regression Algorithm\n")
    evaluate(testing_outputs, predictions, fw)

    classifier = tree.DecisionTreeClassifier()
    classifier.fit(training_inputs, training_outputs)
    predictions = classifier.predict(testing_inputs)

    fw.write("Evaluating Decision Tree Algorithm\n")
    evaluate(testing_outputs, predictions, fw)
    fw.close()

    fr = open(RESULTFILE, "r")
    print(fr.read())

    fr.close()
if __name__ == "__main__":
    main()
