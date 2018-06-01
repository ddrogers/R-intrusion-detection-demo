#########################################
# Intrusion Detection Software in R: Demo
#########################################

## Extract files to one directory and set working directory to 
## "To Source File Location" of RIDS_Demo.R 


## Clusters can be defined numerically as follows:
## DoS == 1
## probe == 2
## r2l == 3
## u2r == 4
## normal == 5
## as determined by the ordered factoring of our code

## Simulation section: ROC Curves
## To better display results a one (normal) vs. all (DoS, probe, r2l, u2r) 
## approach is taken when producing the ROC curves. Due to multiclass ROC plots 
## not being available as of yet in the R language, binary classes have been 
## made for the following cases, i.e. DoS vs. Normal, Probe vs. Normal,
## etc.The cases displayed here are for the DoS vs. Normal and 
## Probe vs. Normal classes of the Train+(20%) and Test+ Data sets. They show 
## how well the algorithm performed in terms of classifying the DoS and Probe 
## classes in conjunction with the normal case, as seen by use of the Sensitvity 
## (true positive rate) and Specificity (false positive rate). A brief description 
## ROC, AUC, and other terms can be found in the "about" section for this tab. 
## The closer to one the AUC value, the better the performance of the algorithm 
## on the set. 

## PIDS section: SVM Classification Plot
## The SVM classifcation plot offers insight into how the Test+ data performs 
## with the PIDS algorithm. Similar to what was seen in our scatter plots, the 
## grouped data points are displayed using the first and second principal component
## as the x and y axis, respectively. We can notice that the groups are still color
## coded as they were in the previous three dimensionsal scatterplot. The main difference 
## between this and our other plots is the addition of the classifcation boundaries
## as defined by our color legend to the right of the plot. As is expected, and as seen 
## in our SVMExample.R script, as the cost and gamma parameters change for our radial
## kernel, so do the boundaries of the classes. It should also be noted here that 
## the 'X' data points represent boundary points, while the 'O' data points reprent the
## data as output by the PIDS algorithm. 

## R Scripts to be included:
## RIDS_Demo.R
## RIDS_bars.R
## kmedexample.R
## SVMexample.R
## RIDS_function.R

## Data sets included: 
## KDDTrain+.txt
## KDDTrain+_20Percent.txt
## KDDTest+.txt

## Documents
## Included in zip file

## Packages Installed:
## gwidgets2
## ggplot2
## rgl
## ROCR
## dplyr
## data.table
## e1071
## caret
## scatterplot3d
## cairoDevice
## magick
## plotly
## heatmaply
## RColorBrewer
## devtools
## curl
## gWidgets2RGtk2
## magrittr
## fromatR
## rprojroot
## rmarkdown
## ggbiplot
## vqv
## cluster
## pROC

## Make Note of any errors here:
##
##
##
##

if(interactive()){
  
  ##########################################
  # Packages to be checked for and installed
  ##########################################
  list.of.packages <- c("gWidgets2", "ggplot2", "rgl", "ROCR", "dplyr", "data.table",
                        "e1071", "caret", "scatterplot3d", "magick", "RColorBrewer",
                        "devtools", "curl","gWidgets2RGtk2", "plotly", "cairoDevice",
                        "magrittr", "heatmaply", "cluster","pROC","pca3d")
  new.packages <- list.of.packages[!(list.of.packages %in% installed.packages()[,"Package"])]
  if(length(new.packages)) install.packages(new.packages)
  
  # Github Package installs
  library(devtools)
  list.of.packages <- c("ggbiplot", "vqv")
  new.packages <- list.of.packages[!(list.of.packages %in% installed.packages()[,"Package"])]
  if(length(new.packages)) install_github("vqv/ggbiplot")
  
  ###########################
  # Check for package updates
  ###########################
  # update.packages()
  
  # load gwidgets2 package
  library(gWidgets2)
  options(guiToolkit = "RGtk2")
  
  ####################
  # Application Layout
  ####################
  
  # Create the window for the application
  win <- gwindow("PIDS Data Mining GUI", visible=FALSE,expand=TRUE,fill=TRUE)
  
  ## List of actions
  ## Here the actions will be open (data set), load (data set), save (data,
  ## results, images, and so on)
  acts <- list(open=gaction("open", icon="open", parent=win),
               save = gaction("save", icon="save", handler=function(...) svalue(sb) <- "save", parent=win),
               undo=gaction("undo", icon="undo", handler=function(...) svalue(sb) <- "undo", parent=win),
               redo=gaction("redo", icon="redo", handler=function(...) svalue(sb) <- "redo", parent=win),
               quit=gaction("quit", icon="quit", handler = function(...) dispose(win), parent = win)
  )
  ## Menu Bar list
  mb_list <- list(File=list(
    acts[[1]],
    acts[[2]],
    gseparator(parent=win),
    acts[[5]]
  ))

  ## Toolbar lists are "flat"
  
  mb <- gmenu(mb_list, cont=win)
  
  sb <- gstatusbar("Predicitive Intrusion Detection System (PIDS)", cont=win)
  
  g <- gvbox(cont=win)
  
  nb <- gnotebook(cont=win, tab.pos = 2)
  
  g <- ggroup(cont=nb,horizontal=FALSE,label="Introduction")
  #about <- "Detailed explanation of each component of research"
  # or gtext(...,width=300,height=300)
  g2 <- gframe("Predictive Intrusion Detection System (PIDS)",cont=g,expand=TRUE,fill=TRUE)
  glabel("
         The Predictive Intrusion Detection System is an R GUI application intended
         to supplement the results of year one of the CSpec-DVE program. Research 
         involved exploration of the NSL-KDD network traffic data set to establish a
         predefined statistical model of prediction for detecting cyber threats on a given
         network. This process involved application of data mining and machine learning 
         method for network analysis and predictions on this type of data.
         
         Users will be introduced to the topics necessary for the completion of the project,
         including principal component analysis, k-medoid clustering, and support vector machines. 
         Each topic is designed to cover a wide range of use and functionality throughout the research
         and will mentioned within portions of this application.
         
         To navigate the application, click the tab of interest to begin your 
         journey of the Predicitve Intrusion Detection System (PIDS).
         ", horizontal=FALSE,expand=TRUE,fill=TRUE, cont=g2)
  
  
  #--------------------------------------------------------------------
  
  ####################
  # Importing the data
  ####################
  source("RIDS_function.R")
  source("RIDS_bars.R")
  
  library(dplyr)
  library(data.table)
  library(cairoDevice)
  
  
  about_data <- "
  Here is where a description of the NSL-KDD data set will go.
  back,buffer_overflow,ftp_write,guess_passwd,imap,ipsweep,land,loadmodule,multihop,neptune,nmap,normal,perl,phf,pod,portsweep,rootkit,satan,smurf,spy,teardrop,warezclient,warezmaster.
  duration: continuous.
  protocol_type: symbolic.
  service: symbolic.
  flag: symbolic.
  src_bytes: continuous.
  dst_bytes: continuous.
  land: symbolic.
  wrong_fragment: continuous.
  urgent: continuous.
  hot: continuous.
  num_failed_logins: continuous.
  logged_in: symbolic.
  num_compromised: continuous.
  root_shell: continuous.
  su_attempted: continuous.
  num_root: continuous.
  num_file_creations: continuous.
  num_shells: continuous.
  num_access_files: continuous.
  num_outbound_cmds: continuous.
  is_host_login: symbolic.
  is_guest_login: symbolic.
  count: continuous.
  srv_count: continuous.
  serror_rate: continuous.
  srv_serror_rate: continuous.
  rerror_rate: continuous.
  srv_rerror_rate: continuous.
  same_srv_rate: continuous.
  diff_srv_rate: continuous.
  srv_diff_host_rate: continuous.
  dst_host_count: continuous.
  dst_host_srv_count: continuous.
  dst_host_same_srv_rate: continuous.
  dst_host_diff_srv_rate: continuous.
  dst_host_same_src_port_rate: continuous.
  dst_host_srv_diff_host_rate: continuous.
  dst_host_serror_rate: continuous.
  dst_host_srv_serror_rate: continuous.
  dst_host_rerror_rate: continuous.
  dst_host_srv_rerror_rate: continuous.
  
  Documentation on feature selection indicates the following variables yield 
  relevant results for both sets in regards to analyzing the data:
  
  Src_bytes
  Service
  Dst_bytes
  flag
  Diff_srv_rate
  Same_srv_rate
  Dst_host_srv_count
  Dst_host_same_srv_rate
  Dst_host_diff_srv_rate
  Dst_host_serror_rate
  Logged_in
  Dst_host_srv_serror_rate
  Serror_rate
  count
  Srv_serror_rate
  
  Reference: 
  - Feature Ranking and Support Vector Machines Classification Analysis of the NSL-KDD Intrusion Detection Corpus
  
  Source (URL): http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html
  "
  
  about_data <- list(Description = about_data)
  
  csv <- data.table(test)
  csv <- sample_n(csv, 1000)
  csv2 <- data.table(train)
  csv2 <- sample_n(csv2, 1000)
  
  ## layout
  pg <- ggroup(cont=nb,label="Data")
  pg$set_borderwidth(10L)
  
  lg <- gvbox(cont=pg, expand=TRUE)
  rg <- gvbox(cont=pg, expand=TRUE)
  
  pg <- gpanedgroup(cont=lg, expand=TRUE, horizontal=FALSE)
  fr <- gvbox(cont=pg, expand=TRUE, fill=TRUE, spacing=5)
  l <- glabel(gettext("Testing Set:"), cont=fr, anchor=c(-1,0))
  font(l) <- list(weight="bold")
  outputtesttab <- gtable(data.table(csv), expand=TRUE, fill=TRUE, cont=fr,width=10)
  
  fr <- gvbox(cont=pg, expand=TRUE, fill=TRUE, spacing=5)
  l <- glabel(gettext("Training Set:"), cont=fr, anchor=c(-1,0))
  font(l) <- list(weight="bold")
  outputtraintab <- gtable(data.table(csv2), expand=TRUE, fill=TRUE,cont=fr)
  
  svalue(pg) <- 0.5
  
  pg <- gpanedgroup(cont=rg, expand=TRUE)
  
  fr <- gvbox(cont=pg, expand=TRUE, fill=TRUE, spacing=5)
  l <- glabel(gettext("Output:"), cont=fr, anchor=c(-1,0))
  font(l) <- list(weight="bold")
  output <- ggraphics(cont=fr,visible=FALSE)
  d <- dev.cur()
  
  svalue(pg) <- 0.5
  
  ## buttons in a button group
  bg <- ggroup(cont=rg)
  addSpring(bg)
  about_btn <- gbutton("about", cont=bg, handler=function(...) {
    w1 <- gwindow("About",  parent=win)
    g <- gvbox(cont=w1); g$set_borderwidth(10L)
    gtable(about_data, cont=g)
    gseparator(cont=g)
    bg <- ggroup(cont=g); addSpring(bg)
    gbutton("dismiss", cont=bg, handler=function(...) dispose(w1))
  })
  run_btn <-  gbutton("Run", container = bg,
                      handler=function(h, ...) {
                        visible(output) <- TRUE
                        bars()
                        ## If a heatmap is wanted instead of bar plot,
                        ## comment out bars() and uncomment one of the 
                        ## following:
                        ## heat(csv)
                        ## heat2(csv)
                        ## heat3(csv)
                      })
  
  
  #----------------------------------------------------------------------
  #----------------------------------------------------------------------
  #----------------------------------------------------------------------
  
  ####################################
  # Principal Component Analysis (PCA)
  ####################################
  library(ggbiplot)
  
  about_pca <- "
  Biplot Description:
  
  Interpreting Points: The relative location of the points can be interpreted. 
  Points that are close together correspond to observations 
  that have similar scores on the components displayed in the plot.
  To the extent that these components fit the data well, the points also 
  correspond to observations that have similar values on the variables.
  
  Interpreting Vectors: Both the direction and length of the vectors can be interpreted. 
  Vectors point away from the origin in some direction.
  
  A vector points in the direction which is most like the variable represented by the vector. 
  This is the direction which has the highest squared multiple correlation with the principal components. 
  The length of the vector is proportional to the squared multiple correlation between the fitted values 
  for the variable and the variable itself.
  
  The fitted values for a variable are the result of projecting the points in the space orthogonally onto 
  the variable's vector (to do this, you must imagine extending the vector in both directions). The observations 
  whose points project furthest in the direction in which the vector points are the observations that have the 
  most of whatever the variable measures. Those points that project at the other end have the least. Those projecting 
  in the middle have an average ammount. then the
  
  Thus, vectors that point in the same direction correspond to variables that have similar response profiles, and can 
  be interpreted as having similar meaning in the context set by the data.
  
  Reference:Copyright © 1999 by Forrest W. Young
  
  Source (URL): http://forrest.psych.unc.edu/research/vista-frames/help/lecturenotes/lecture13/biplot.html
  "
  about_pca = list(Description=about_pca)
  
  ## layout
  pgpca <- ggroup(cont=nb,label="PCA")
  
  #g <- gnotebook(cont=pg2)
  
  lgpca <- gvbox(cont=pgpca, expand=TRUE)
  rgpca <- gvbox(cont=pgpca, expand=TRUE)
  
  pgpca <- gpanedgroup(cont=lgpca, expand=TRUE, horizontal=FALSE)
  
  frpca <- gvbox(cont=pgpca, expand=TRUE, fill=TRUE, spacing=5)
  lpca <- glabel(gettext("Iris Data:"), cont=frpca, anchor=c(-1,0))
  font(lpca) <- list(weight="bold")
  outputpcatab <- gtable(data.table(iris), expand=TRUE, fill=TRUE, cont=frpca,width=10)
  
  ## Iris PCA Example
  
  # log transform 
  log.ir <- log(iris[, 1:4])
  ir.species <- iris[, 5]
  
  # apply PCA - scale. = TRUE is highly 
  # advisable, but default is FALSE. 
  ir.pca <- prcomp(log.ir,
                   center = TRUE,
                   scale. = TRUE) 
  
  frpca <- gvbox(cont=pgpca, expand=TRUE, fill=TRUE, spacing=5)
  lpca <- glabel(gettext("Loadings (or rotations):"), cont=frpca, anchor=c(-1,0))
  font(lpca) <- list(weight="bold")
  outputpca <- gtable(data.table(ir.pca$x), expand=TRUE, fill=TRUE,cont=frpca)
  
  svalue(pgpca) <- 0.5
  
  pgpca <- gpanedgroup(cont=rgpca, expand=TRUE)
  
  frpca <- gvbox(cont=pgpca, expand=TRUE, fill=TRUE, spacing=5)
  lpca <- glabel(gettext("Output:"), cont=frpca, anchor=c(-1,0))
  font(lpca) <- list(weight="bold")
  outputpcagraph <- ggraphics(cont=frpca, with=300, height=600,visible=FALSE)
  dpca <- dev.cur()
  
  svalue(pgpca) <- 0.5
  
  ## buttons in a button group
  bgpca <- ggroup(cont=rgpca)
  addSpring(bgpca)
  about_btnpca <- gbutton("about", cont=bgpca, handler=function(...) {
    w1 <- gwindow("About",  parent=win)
    g <- gvbox(cont=w1); g$set_borderwidth(10L)
    gtable(about_pca, cont=g)
    gseparator(cont=g)
    bg <- ggroup(cont=g); addSpring(bg)
    gbutton("dismiss", cont=bg, handler=function(...) dispose(w1))
  })
  
  run_btnpca <-  gbutton("Run", container = bgpca,
                         handler=function(h, ...) {
                           visible(outputpcagraph) <- TRUE
                           g <- ggbiplot(ir.pca, obs.scale = 1, var.scale = 1, 
                                         groups = ir.species, ellipse = TRUE, 
                                         circle = TRUE) +
                             ggtitle("PCA Biplot on Iris Data Set")
                           g <- g + scale_color_discrete(name = '')
                           g <- g + theme(legend.direction = 'horizontal', 
                                          legend.position = 'top')
                           print(g)
                         })
  
  #----------------------------------------------------------------------
  #----------------------------------------------------------------------
  #----------------------------------------------------------------------
  
  ###########
  # k-medoids
  ###########
  source("kmedExample.R")
  
  library(cluster)
  
  about_kmed <- "
  K-medoids:
  A classical partitioning technique of clustering that clusters the data set of n objects 
  into k clusters known a priori. A useful tool for determining k is the silhouette.
  

  Source (URL): https://en.wikipedia.org/wiki/K-medoids
  "
  
  about_kmed <- list(Description = about_kmed)
  
  pgkmed <- ggroup(cont=nb,label="K-medoids")
  
  lgkmed <- gvbox(cont=pgkmed, expand=TRUE)
  rgkmed <- gvbox(cont=pgkmed, expand=TRUE)
  
  
  ## Left Pane Group
  ## use a form layout for ease in laying out the controls to adjust the
  ## arguments for `sim.pids`
  
  lkmed <- glabel(gettext("Parameters:"),cont=lgkmed,anchor=c(-1,0))
  font(lkmed) <- list(weight="bold")
  
  flytkmed <- gformlayout(cont=lgkmed)
  addSpring(lgkmed)
  
  clust <- c(1:5)
  
  #num_clust <- gradio(clust, horizontal = TRUE, cont=flytkmed,label="Clusters")
  num_clust <- gcombobox(clust, selected = 3, cont=flytkmed, label="Clusters")
  
  # Possibly convert to dropdown option
  dissmat <- gradio(c("No", "Yes"), horizontal = TRUE, cont=flytkmed, label="Distance Matrix")
  
  
  
  ## Right Pane Group
  pgkmed <- gpanedgroup(cont=rgkmed, expand=TRUE)
  
  frkmed <- gvbox(cont=pgkmed, expand=TRUE, fill=TRUE, spacing=5)
  lkmed <- glabel(gettext("Output:"), cont=frkmed, anchor=c(-1,0))
  font(lkmed) <- list(weight="bold")
  outputkmed <- ggraphics(cont=frkmed,visible=FALSE)
  dkmed <- dev.cur()
  
  frkmed <- gvbox(cont=rgkmed, expand=TRUE, fill=TRUE, spacing=5)
  lkmed <- glabel(gettext("Motor Trend Cars:"), cont=frkmed, anchor=c(-1,0))
  font(lkmed) <- list(weight="bold")
  outputtabkmed <- gtable(data.table(cars.data2), expand=TRUE, fill=TRUE, cont=frkmed)
  
  ## Buttons Group
  bgkmed <- ggroup(cont=rgkmed)
  addSpring(bgkmed)
  
  about_btnkmed <- gbutton("about", cont=bgkmed, handler=function(...) {
    w1 <- gwindow("About",  parent=win)
    g <- gvbox(cont=w1); g$set_borderwidth(10L)
    gtable(about_kmed, cont=g)
    gseparator(cont=g)
    bg <- ggroup(cont=g); addSpring(bg)
    gbutton("dismiss", cont=bg, handler=function(...) dispose(w1))
  })
  
  run_btnkmed <-  gbutton("Run", container = bgkmed,
                          handler=function(h, ...) {
                            nc <<- svalue(num_clust)
                            if(svalue(dissmat) == "Yes") {diss <<- TRUE} else diss <<- FALSE
                            if(nc != " "){
                              visible(outputkmed) <- TRUE
                              kmclust(nc,diss)
                              }
                            
                          })
  #----------------------------------------------------------------------
  #----------------------------------------------------------------------
  #----------------------------------------------------------------------
  
  ##############################
  # Support Vector Machine (SVM)
  ##############################
  source("SVMExample.R")
  
  about_svm <- "
  A Support Vector Machine (SVM) is a discriminative classifier formally defined by a separating hyperplane. 
  In other words, given labeled training data (supervised learning), the algorithm outputs an optimal hyperplane which categorizes new examples.

  Source (URL): http://docs.opencv.org/2.4/doc/tutorials/ml/introduction_to_svm/introduction_to_svm.html
  "
  about_svm <- list(Description = about_svm)
  
  pgsvm <- ggroup(cont=nb,label="SVM")
  
  lgsvm <- gvbox(cont=pgsvm,expand=TRUE)
  rgsvm <- gvbox(cont=pgsvm, expand=TRUE,fill=TRUE)
  
  ## Right Pane Group
  pgsvm <- gpanedgroup(cont=rgsvm, expand=TRUE)
  
  frsvm <- gvbox(cont=pgsvm, expand=TRUE, fill=TRUE, spacing=5)
  lsvm <- glabel(gettext("Output:"), cont=frsvm, anchor=c(-1,0))
  font(lsvm) <- list(weight="bold")
  outputsvm <- ggraphics(cont=frsvm,visible=FALSE)
  dsvm <- dev.cur()
  
  
  ## Left Pane Group
  lsvm <- glabel(gettext("Parameters:"),cont=lgsvm,anchor=c(-1,0))
  font(lsvm) <- list(weight="bold")
  
  flytsvm <- gformlayout(cont=lgsvm)
  addSpring(lgsvm)
  
  kernelsvm <- c("radial"="radial", "linear"="linear", "polynomial"="polynomial", "sigmoid"="sigmoid")
  
  kernel_choicesvm <- gcombobox(names(kernelsvm), selected = 1, cont=flytsvm, label="Kernel")
  
  costsvm <- c(10^(-1:2))
  
  cost_choicesvm <- gcombobox(costsvm, selected = 2, cont=flytsvm, label="Cost")
  
  gammasvm <- c(0.5,1,2)
  
  gamma_choicesvm <- gcombobox(gammasvm, selected = 1, cont=flytsvm, label="Gamma")
  
  ## Buttons Group
  bgsvm <- ggroup(cont=rgsvm)
  addSpring(bgsvm)
  
  about_btnsvm <- gbutton("about", cont=bgsvm, handler=function(...) {
    w1 <- gwindow("About",  parent=win)
    g <- gvbox(cont=w1); g$set_borderwidth(10L)
    gtable(about_svm, cont=g)
    gseparator(cont=g)
    bg <- ggroup(cont=g); addSpring(bg)
    gbutton("dismiss", cont=bg, handler=function(...) dispose(w1))
  })
  
  run_btnsvm <-  gbutton("Run", container = bgsvm,
                         handler=function(h, ...) {
                           ksvm <<- svalue(kernel_choicesvm) 
                           csvm <<- svalue(cost_choicesvm)
                           gsvm <<- svalue(gamma_choicesvm)
                           visible(outputsvm) <- TRUE
                           SVMEx(kernel = ksvm, cost = csvm, gamma = gsvm)
                         })
  
  
  
  #------------------------------------------------------------------
  #----------------------------------------------------------------------
  #----------------------------------------------------------------------
  
  ## Source the R file to use functions within pids_function
  #source("pids_function3_2.R")
  
  library(magrittr)
  library(plotly)
  library(pROC)
  ################
  # Simulation Run
  ################
  
  about_sim <- "Description of ROC Curves and the statistical measures used to validate
  PIDS, i.e. AUC, accuracy, true posititive rate, false positive rate, confusion matrix, etc.
  
  Terminology:  

  Confusion Matrix, or error matrix: table used to describe the performance of a classification model on a set of test data where the true values are known.
  
  Accuracy: measure of statistical bias that shows how often the classifier correctly predicts the referenced values.

  Sensitivity, or true positive value: measures the proportion of positives that are correctly identified.
  
  Specificity, or true negative rate: measures the proportion of negative values that are correctly identified.
  
  Receiver Operating Characteristic (ROC): plot that visualizes the performance of a classifier, i.e. the output of the SVM.
  
  Area Under the Curve (AUC): value that aids in determining how well the classification model predicts classes.
  
  Precision, or positive predictive value,: the percent of how often the classifier correctly predicts the referenced values. 
  
  Class Distribution:
  
  Three dimensional scatterplot of PCA with k-medoids clustering: 
  
  Notice here that the when computing the principal components and clusters of our Train+(20%) and Test+ data sets, the resulting
  scatterplot appears to show an equal distribution of the data between our 5 class. However, referring back to our bar plot of the 
  the test at the beginning of application, we know this is not the case. In consideration of the data, it is in the best interest 
  of the research to add weights to our data to yield the best results of our proposed algorithm. Since this can further affect the 
  results of our algorithms accuracy, research numerous weight distribution technique should be considered
  for application prior to the building of our support vector machine (SVM) model.

  Parameter Selection:
  
  Preprocessing:
  
  The NSL-KDD data sets were preprocessed using a min-max normalization techinique in conjuction
  with procedure that removed an non-numeric variables and converted any factor variables into 
  numeric ones. The 24 attack classes available in each data set are categorized into one of four 
  classes, i.e. DoS, u2R, r2l, or probe. 
  
  Alternative methods of preprocessing, i.e. centering, scaling, are to be considered in future 
  updates for additional parts of the algorithm, i.e. PCA, k-medoids, or SVM.
  
  PCA:
  
  The principal component analysis function uses a correlation based feature selection to reduce our
  data sets of 41 variables down to 6 in the case of the Train+ and Train+_20Percent data sets and 
  7 in the case of the Test+ training set, with the set of component variables explaining 100% of the 
  variance within each set.
  
  k-medoids:
  
  The k-medoids clustering algorithm has a number of parameters, each of which vary depending on the 
  clusteering method used, i.e. PAM (Partitioning Around Medoids), CLARA (Clustering Large Applications),
  or an additional method. Determining which to use is a matter of the number of observations provided in 
  each data set. Documented in the R help file reference for PAM and CLARA it is noteable to use the PAM 
  algorithm for data sets with less than 2000 observations and the CLARA algorithm otherwise.
  
  Parameters to be noted in PAM are diss, metric, medoids, stand, and do.swap.
  Parameters to be noted in CLARA are metric, stand, samples, and samplesize. 
  Each carry a unique weight on how the clustering results are output for the two algorithms.
  Given the dimensions of all sets are well over 2000, CLARA will be used for the clustering portion of
  the algorithm.
  
  Support Vector Machine (SVM):
  
  The support vector machine portion has two functions that are of use in the algorithm, the tuning and SVM 
  classifying algorithms. Both have similar parameters that play a key role in the identification of observations 
  as one of the five classes. Parameters of concern are scale, type, kernel, degree, gamma,
  coef0, cost, nu, and class.weights. Each parameter is significant in providing the development of the best 
  model for classifcation in both the training and test set. Parameters that may have the most affect on this research
  are cost, gamma, and class.weights since each set has a varying distribution of each class. Results of the 
  SVM are then placed in a multiclass confusion matrix which the computes additional values, i.e. specificity
  (true positive rate) and fall-out (True-negative results) for the output of receiver operating characteristic (ROC)
  curves and area under the curve (AUC) values. Both are used in performance testing the algorithm on the Train+ and Test+
  sets.
  
  "
  
  about_sim <- list(Description=about_sim)
  
  ## Layout
  pgsim <- ggroup(cont=nb, label="Simulation")
  pgsim$set_borderwidth(10L)
  
  lgsim <- gvbox(cont=pgsim, expand=TRUE)
  rgsim <- gvbox(cont=pgsim, expand=TRUE, fill=TRUE)
  
  ## Visual Output Windows
  pgsim <- gpanedgroup(cont=rgsim, expand=TRUE, horizontal=FALSE)
  frsim <- gvbox(cont=pgsim, expand=TRUE, fill=TRUE, spacing=5)
  lsim <- glabel(gettext("ROC Curves:"), cont=frsim, anchor=c(-1,0))
  font(lsim) <- list(weight="bold")
  outputsim <- ggraphics(cont=frsim,visible=FALSE, height = 500, width = 300)
  dsim <- dev.cur()
  
  
  
  ## use a form layout for ease in laying out the controls to adjust the
  ## arguments for `sim.pids`
  
  lsim <- glabel(gettext("Parameters:"),cont=lgsim, anchor=c(-1,0))
  font(lsim) <- list(weight="bold")
  
  flytsim <- gformlayout(cont=lgsim)
  addSpring(lgsim)
  
  # sim <- c(1:10)
  
  # num_sim <- gcombobox(sim, selected = 1, cont=flytsim, label="Trials")
  # Number of Classes Anticipated
  clustsim <- c(1:10)
  
  clust_sim <- gcombobox(clustsim, selected = 5, cont=flytsim, label = "Classes") 
    
  kernelsim <- c("radial"="radial", "linear"="linear", "polynomial"="polynomial", "sigmoid"="sigmoid")
  
  ker_choicesim <- gcombobox(names(kernelsim), selected = 1, cont=flytsim, label="Kernel")
  
  costsim <- c(2^(-8:6))
  
  cost_choicesim <- gcombobox(costsim, selected = 15, cont=flytsim, label="Cost")
  
  gammasim <- c(1/2^(-8:6))
  
  gamma_choicesim <- gcombobox(gammasim, selected = 14, cont=flytsim, label="Gamma")
  
  ## Table of accuracy outputs
  
  frsim <- gvbox(cont=pgsim, expand=TRUE, fill=TRUE, spacing=5)
  lsim <- glabel(gettext("Results:"), cont=frsim, anchor=c(-1,0))
  font(lsim) <- list(weight="bold")
  
  ## interactions
  ## buttons in a group
  bgsim <- ggroup(cont=rgsim)
  addSpring(bgsim)
  about_btnsim <- gbutton("about", cont=bgsim, handler=function(...) {
    w1 <- gwindow("About",  parent=win)
    g <- gvbox(cont=w1); g$set_borderwidth(10L)
    gtable(about_sim, cont=g)
    gseparator(cont=g)
    bg <- ggroup(cont=g); addSpring(bg)
    gbutton("dismiss", cont=bg, handler=function(...) dispose(w1))
  })
  
  run_btnsim <-  gbutton("Run", container = bgsim,
                         handler=function(h, ...) {
                           #ns <<- svalue(num_sim)
                           ncsim <<- svalue(clust_sim)
                           ksim <<- svalue(ker_choicesim) 
                           csim <<- svalue(cost_choicesim)
                           gsim <<- svalue(gamma_choicesim)
                           visible(outputsim) <- TRUE
                           results <- sim.pids3.1(no.clust = ncsim,kernel=ksim,cost=csim,gamma=gsim)
                           outputsimtab <<- gtable(data.table(results$Acc.Tab.ByClass), expand=TRUE, fill=TRUE, cont=frsim,width=10)
                         })
  
  #-------------------------------------------------------------------
  #-------------------------------------------------------------------
  #-------------------------------------------------------------------
  ##########
  # Run PIDS
  ##########
  
  about_pids <- "Description of the methods and algorithms used during the 
  research, i.e. preprocessing, PCA, k-medoids, SVM with necessary formulas
  and combined PIDS formula
  
  Description of variables used in the NSL-KDD data set [1]
  
  NSL-KDD
  
  Attacks fall into four main categories:
  
  - DOS: denial-of-service, e.g. syn flood;
  - R2L: unauthorized access from a remote machine, e.g. guessing 
  password;
  - U2R: unauthorized access to local superuser (root) privileges, 
  e.g., various ``buffer overflow'' attacks;
  - probing: surveillance and other probing, e.g., port scanning.
  
  Data files 
  
  - KDDTrain+.TXT: The full NSL-KDD train set including attack-type
  labels and difficulty level in CSV format
  - KDDTrain+_20Percent.TXT: A 20% subset of the KDDTrain+.txt file
  - KDDTest+.TXT: The full NSL-KDD test set including attack-type 
  labels and difficulty level in CSV format
  Improvements to the KDD'99 dataset:
  
  The NSL-KDD data set has the following advantages over the original KDD data set:
  
  - It does not include redundant records in the train set, so the classifiers 
  will not be biased towards more frequent records.
  - There is no duplicate records in the proposed test sets; 
  therefore, the performance of the learners are not biased by the 
  methods which have better detection rates on the frequent records.
  - The number of selected records from each difficultylevel group is 
  inversely proportional to the percentage of records in the original KDD data set.
  As a result, the classification rates of distinct machine learning methods vary 
  in a wider range, which makes it more efficient to have an accurate evaluation 
  of different learning techniques.
  - The number of records in the train and test sets are reasonable, which makes it 
  affordable to run the experiments on the complete set without the need to randomly 
  select a small portion. Consequently, evaluation results of different research works 
  will be consistent and comparable.
  
  Algorithm:
  
  Preprocessing: The Train+ data set acts as a type of predefined dictionary data for the model
  to be built on. The Test+ data set will be combined with the Train+ set, both having their category
  column removed. The idea here is that if the data is process, analyzed, and clustered together, the 
  resulting SVM model built will have a stronger affinity to higher accuracy on the Test+ data when
  separated.
  
  Principal Component Analysis (PCA): Dimensionally reduces the data from 41 variables to 6 or 7 principal components for analysis. With
  100% of the variance exaplined in the data by the group of components, the resulting set is then grouped
  using k-medoid clustering. 
  
  k-medoid clustering: PCA data is grouped into one of 5 classes, i.e. DoS, u2r, r2l, probe, or normal. The 
  resulting clusters are then stored and the full data set is separated into the Train+ and Test+ sets,
  respectively, in preparation for classification via SVM. 
  
  Support Vector Machine (SVM): For each cluster, an SVM model is trained for each cluster labeled in Train+ 
  to be applied to each cluster labeled in the Test+ set. The accuracy of both sets are computed using a multilass 
  confusion matrix.  
  
  References: 
  [1] M. Tavallaee, E. Bagheri, W. Lu, and A. Ghorbani, 'A Detailed Analysis of the KDD CUP 99 Data Set' 
  Submitted to Second IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA), 2009.
  
  "
  about_pids <- list(Description = about_pids)
  
  ## layout
  pgpids <- ggroup(cont=nb,label="PIDS")
  pgpids$set_borderwidth(10L)
  
  lgpids <- gvbox(cont=pgpids, expand=TRUE)
  rgpids <- gvbox(cont=pgpids, expand=TRUE, fill=TRUE)
  
  
  
  ## interactions
  
  ## Visual Output Windows
  pgpids <- gpanedgroup(cont=rgpids, expand=TRUE, horizontal=FALSE)
  frpids <- gvbox(cont=pgpids, expand=TRUE, fill=TRUE, spacing=5)
  lpids <- glabel(gettext("PCA Plot:"), cont=frpids, anchor=c(-1,0))
  font(lpids) <- list(weight="bold")
  outputpids <- ggraphics(cont=frpids, visible=FALSE, height = 500, width = 300)
  dpids <- dev.cur()
  
  ## use a form layout for ease in laying out the controls to adjust the
  ## arguments for `predictive.ids`
  
  lpids <- glabel(gettext("Parameters:"),cont=lgpids, anchor=c(-1,0))
  font(lpids) <- list(weight="bold")
  
  flytpids <- gformlayout(cont=lgpids)
  addSpring(lgpids)
  
  
  
  kernelpids <- c("radial"="radial", "linear"="linear", "polynomial"="polynomial", "sigmoid"="sigmoid")
  
  kernel_choicepids <- gcombobox(names(kernelpids), selected = 1, cont=flytpids, label="Kernel")
  
  costpids <- c(2^(-8:6))
  
  cost_choicepids <- gcombobox(costpids, selected = 15, cont=flytpids, label="Cost")
  
  gammapids <- c(1/2^(-8:6))
  
  gamma_choicepids <- gcombobox(gammapids, selected = 14, cont=flytpids, label="Gamma")
  
  ## Table of predicted outputs
  
  frpids <- gvbox(cont=pgpids, expand=TRUE, fill=TRUE, spacing=5)
  lpids <- glabel(gettext("Results:"), cont=frpids, anchor=c(-1,0))
  font(lpids) <- list(weight="bold")
  #outputpidstab <- gtable(data.table(), expand=TRUE, fill=TRUE, cont=frpids,visible= FALSE) 
  
  ## buttons in a group
  bgpids <- ggroup(cont=rgpids)
  addSpring(bgpids)
  
  ## "about" button
  about_btnpids <- gbutton("about", cont=bgpids, handler=function(...) {
    w1 <- gwindow("About",  parent=win)
    g <- gvbox(cont=w1); g$set_borderwidth(10L)
    gtable(about_pids, cont=g,expand=TRUE)
    gseparator(cont=g)
    bg <- ggroup(cont=g); addSpring(bg)
    gbutton("dismiss", cont=bg, handler=function(...) dispose(w1))
  })
  run_btnpids <-  gbutton("Run", container = bgpids,
                          handler=function(h, ...) {
                            kpids <<- svalue(kernel_choicepids)
                            cpids <<- svalue(cost_choicepids)
                            gpids <<- svalue(gamma_choicepids)
                            visible(outputpids) <- TRUE
                            #visible(outputpidstab) <- TRUE
                            results <- predictive.ids3.0(kernel=kpids,cost=cpids,gamma=gpids)$AttConnections
                            outputpidstab <<- gtable(data.table(results), expand=TRUE, fill=TRUE, cont=frpids)
                          })
  
  
  #-------------------------------------------------------------------
  #-------------------------------------------------------------------
  #-------------------------------------------------------------------
  
  
  ######################################
  # Exception Handling (Where necessary)
  ######################################
  #size(win) <- c(600,800)
  visible(win) <- T 
}