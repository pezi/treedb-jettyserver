/*
* (C) Copyright 2014,2016 Peter Sauer (http://treedb.at/).
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 */
package at.treedb;

import java.awt.AWTException;
import java.awt.Desktop;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.GroupLayout;
import javax.swing.ImageIcon;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.text.MaskFormatter;

import org.eclipse.jetty.runner.Runner;

import com.apple.eawt.Application;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.JButton;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Image;
import javax.swing.JTextArea;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JMenuBar;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JCheckBox;
import javax.swing.JFormattedTextField;

/**
 * <p>
 * Jetty server with GUI for testing out-of-the-box the TreeDB.<br>
 * Repository for the jetty-runner:<br>
 * http://mvnrepository.com/artifact/org.eclipse.jetty/jetty-runner<br>
 * Layout: Eclipse WindowBuilder<br>
 * https://eclipse.org/windowbuilder/
 * </p>
 * 
 * @author Peter Sauer
 *
 */
@SuppressWarnings("serial")
public class JettyServer extends JFrame {
	private static String jarPath;
	private static Pattern ip4pattern = Pattern
			.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

	private static String JDBC_H2 = "jdbc:h2:PATH/db/treedb";
	private static String HIBERNATE_WAR = "TreeDBhibernate.war";
	private static String ECLIPSELINK_WAR = "TreeDBeclipseLink.war";

	private JTextField warPath;
	private JTextField jdbcURL;
	private JTextField serverURL;
	private JTextField dbUser;
	private JTextField treedbAdmin;
	private JPasswordField dbUserPwd;
	private JPasswordField treedbAdminPwd;
	private JFormattedTextField httpPort;
	private JTextField context;
	private JCheckBox uiLook;

	public enum Field {
		WAR_PATH, IP_ADDRESS, PORT, JDBC_URL, DBUSER, DBUSERPWD, PERSISTENCE, ADMINPWD, UILOOK
	};

	private HashMap<Field, JComponent> fieldMap = new HashMap<Field, JComponent>();;

	private ArrayList<String> ipList;
	private JComboBox<?> databaseList;
	private JComboBox<?> ip4List;
	private JComboBox<?> persistenceLayerList;
	private JButton startServer;
	private JButton stopServer;
	private JComboBox<?> ddl;;
	private static String tmpDir;
	private JTextArea logArea;
	private JButton openBrowser;
	private JMenuItem menuHelp;
	private JMenu mainMenu;
	private JScrollPane scrollPaneLog;
	private HelpWindow help;
	private HelpWindow about;

	/**
	 * Helper class for shutting down the Jetty server
	 */
	private static class ShutDownHook extends Thread {
		public void run() {
			if (tmpDir != null) {
				try {
					delete(new File(tmpDir));
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	private static void delete(File f) throws IOException {
		if (f.isDirectory()) {
			for (File c : f.listFiles())
				delete(c);
		}
		if (!f.delete()) {
			System.out.println("Failed to delete file: " + f);
		}
	}

	/**
	 * Launch the application.
	 * 
	 * @throws URISyntaxException
	 */
	public static void main(String[] args) throws Exception {
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		jarPath = JettyServer.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
		jarPath = jarPath.substring(1, jarPath.lastIndexOf("/")) + "/";
		// setup a temporary directory inside the OoB directory
		tmpDir = jarPath + "tmp";
		File tDir = new File(tmpDir);
		if(tDir.exists()) {
			delete(tDir);
		}
		tDir.mkdirs();
		System.setProperty("java.io.tmpdir", tmpDir);
		
		// open frame
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					ShutDownHook jvmShutdownHook = new ShutDownHook();
					Runtime.getRuntime().addShutdownHook(jvmShutdownHook);
					JettyServer frame = new JettyServer();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Checks if an IP address is a valid IP4 address.
	 * 
	 * @param ip
	 *            ip address
	 * @return {@code true} if the IP4 address is valid, {@code false} if not
	 */
	public static boolean isValidIP4(String ip) {
		if (ip == null || ip.isEmpty())
			return false;
		ip = ip.trim();
		if ((ip.length() < 6) & (ip.length() > 15))
			return false;
		try {
			Matcher matcher = ip4pattern.matcher(ip);
			return matcher.matches();
		} catch (PatternSyntaxException ex) {
			return false;
		}
	}

	/**
	 * Opens an URI inside the default browser
	 * 
	 * @param uri
	 */
	public void openWebpage(URI uri) {
		Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
		if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
			try {
				desktop.browse(uri);
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			JOptionPane.showMessageDialog(this, "Unable to open the default browser!");
		}
	}

	/**
	 * Opens an URL inside the default browser
	 * 
	 * @param url
	 */
	public void openWebpage(URL url) {
		try {
			openWebpage(url.toURI());
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Updates the JDBC URL field.
	 */
	public void updateJDBCurl() {
		String war = warPath.getText().trim();
		if (!war.isEmpty()) {
			File f = new File(war);
			if (!f.exists()) {
				return;
			}
			String path = f.getAbsolutePath().replace("\\", "/");
			int pos = path.lastIndexOf("/");
			if (pos != -1) {
				path = path.substring(0, pos);
			}

			String db = (String) databaseList.getSelectedItem();
			if (db.equals("H2")) {
				jdbcURL.setText(JDBC_H2.replace("PATH", path));
			}
		}
	}

	/**
	 * Updates the server URL field.
	 */
	public void updateServerURL() {
		if (ipList.size() == 1) {
			return;
		}
		String url = "http://";
		String ip = (String) ip4List.getSelectedItem();
		String port = httpPort.getText().trim();
		if (ip.equals("all")) {
			String tmp = null;
			for (String addr : ipList) {
				if (addr.equals("localhost")) {
					tmp = addr;
					break;
				}
			}
			if (tmp == null) {
				tmp = ipList.get(1);
			}
			url += tmp;
		} else {
			url += ip;
		}
		if (!port.equals("80")) {
			url += ":" + port;
		}
		url += "/";
		url += context.getText();
		serverURL.setText(url);
	}

	/**
	 * Shuts down the Jetty server
	 * 
	 * @param port
	 *            communication port
	 * @param stopKey
	 *            stop key
	 * @throws IOException
	 */
	public static void attemptShutdown(int port, String stopKey) throws IOException {
		Socket s = new Socket(InetAddress.getByName("localhost"), port);
		try {
			OutputStream out = s.getOutputStream();
			out.write((stopKey + "\r\nstop\r\n").getBytes());
			out.flush();
		} finally {
			s.close();
		}
	}

	/**
	 * Helper class for monitoring the log stream.
	 */
	private class Interceptor extends PrintStream {
		public Interceptor(OutputStream out) {
			super(out, true);
		}

		@Override
		public void print(String s) {
			logArea.append(s + "\n");
			if (s.contains("Started @")) {
				openBrowser.setEnabled(true);
				startServer.setEnabled(false);
				stopServer.setEnabled(true);
			}
		}
	}
	
	/**
	 * Start Jetty server
	 */
	public void startServer() {
		Thread thread = new Thread() {
			public void run() {
				String port = httpPort.getText().trim();

				try {
					URL url = new URL(serverURL.getText());
					URLConnection conn = url.openConnection();
					conn.setConnectTimeout(1000);
					conn.setReadTimeout(1000);
					conn.connect();
					JOptionPane.showMessageDialog(JettyServer.this, "Port " + port + " is in use!");
					return;
				} catch (Exception ex) {

				}
				StringBuffer db = new StringBuffer();
				String player = ((String) persistenceLayerList.getSelectedItem()).toLowerCase();
				if (player.equals("hibernate")) {
					db.append("HIBERNATE|null|");
				} else {
					db.append("JPA|");
					if (player.contains("eclipse")) {
						db.append("ECLIPSELINK|");
					} else {
						db.append("HIBERNATEJPA|");
					}
				}
				db.append(((String) databaseList.getSelectedItem()).toUpperCase());
				db.append("|");
				db.append(((String) ddl.getSelectedItem()).toUpperCase());
				db.append("|");
				db.append(jdbcURL.getText());
				db.append("|");
				db.append(dbUser.getText());
				db.append("|");
				db.append(dbUserPwd.getPassword());

				// redirect out and err stream to the log area
				PrintStream origOut = System.out;
				PrintStream interceptor = new Interceptor(origOut);
				System.setOut(interceptor);
				PrintStream origErr = System.err;
				PrintStream interceptor2 = new Interceptor(origErr);
				System.setErr(interceptor2);

				String warFile = warPath.getText().trim();
				if (warFile.isEmpty()) {
					JOptionPane.showMessageDialog(JettyServer.this, "Missing WAR file");
					return;
				}
				File file = new File(warFile);
				if (!file.exists() || !file.isFile()
						|| !file.getAbsolutePath().toLowerCase().endsWith(".war")) {
					JOptionPane.showMessageDialog(JettyServer.this, "WAR file doesn't exist");
					return;
				}
				// store some TreeDB values
				Properties props = System.getProperties();
				props.setProperty("treedb.database", db.toString());
				props.setProperty("treedb.adminPassword", new String(treedbAdminPwd.getPassword()));
				ArrayList<String> list = new ArrayList<String>();

				// setup the JettyServer
				StringBuffer cmds = new StringBuffer("--stats unsecure --stop-port 8181 --stop-key treedb");
				if (!port.equals("8080")) {
					cmds.append(" --port ");
					cmds.append(port);
				}

				String host = (String) ip4List.getSelectedItem();
				if (!host.equals("all")) {
					cmds.append(" --host ");
					cmds.append(host);
				}

				for (String s : cmds.toString().split(" ")) {
					list.add(s);
				}
				list.add("--path");
				list.add("/TreeDB");
				list.add(warFile);
				// call main method
				Runner.main(list.toArray(new String[list.size()]));
			}
		};
		thread.start();
	}

	/**
	 * Constructor
	 * 
	 * @throws IOException
	 * @throws AWTException 
	 * @throws ParseException 
	 */
	public JettyServer() throws IOException, AWTException, ParseException {
		setTitle("TreeDB Jetty Server");

		// create list of available IP4 addresses
		Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
		ipList = new ArrayList<String>();
		ipList.add("all");
		for (NetworkInterface ni : Collections.list(nets)) {
			Enumeration<InetAddress> inetAddresses = ni.getInetAddresses();
			for (InetAddress inetAddress : Collections.list(inetAddresses)) {
				String ip = inetAddress.getHostAddress();
				if (isValidIP4(ip)) {
					if (ip.equals("127.0.0.1")) {
						ipList.add("localhost");
					} else {
						ipList.add(ip);
					}
				}
			}
		}

		// set different icons
		ArrayList<Image> iconList = new ArrayList<Image>();
		iconList.add(new ImageIcon(getClass().getResource("/images/database16.png")).getImage());
		iconList.add(new ImageIcon(getClass().getResource("/images/database48.png")).getImage());
		setIconImages(iconList);

		Image treeIcon = new ImageIcon(getClass().getResource("/images/TreeDB2.png")).getImage();
		// set dock icon Mac
		if(System.getProperty("os.name").indexOf("Mac") >= 0) {
			Application application = Application.getApplication();
			application.setDockIconImage(treeIcon);
		}
		
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 623, 415);

		JLabel lblWarFile = new JLabel("WAR file");
		lblWarFile.setFont(new Font("Tahoma", Font.BOLD, 12));

		JLabel lblServerIp = new JLabel("Server IP");
		lblServerIp.setFont(new Font("Tahoma", Font.BOLD, 12));

		JLabel lblServerUrl = new JLabel("Server URL");
		lblServerUrl.setFont(new Font("Tahoma", Font.BOLD, 12));

		JLabel lblPersistenceLayer = new JLabel("Persistence Layer");
		lblPersistenceLayer.setFont(new Font("Tahoma", Font.BOLD, 12));

		JLabel lblJdbcUrl = new JLabel("JDBC URL");
		lblJdbcUrl.setFont(new Font("Tahoma", Font.BOLD, 12));

		JLabel lblDatabaseUser = new JLabel("Database User");
		lblDatabaseUser.setFont(new Font("Tahoma", Font.BOLD, 12));

		JLabel lblTreedbAdmin = new JLabel("TreeDB Admin");
		lblTreedbAdmin.setFont(new Font("Tahoma", Font.BOLD, 12));

		startServer = new JButton("Start Server");

		startServer.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {			
				startServer();
			}
		});

		stopServer = new JButton("Stop Server & GUI");
		stopServer.setEnabled(false);
		stopServer.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					attemptShutdown(8181, "treedb");
				} catch (IOException e1) {
					e1.printStackTrace();
				}
			}
		});

		openBrowser = new JButton("Open Browser");
		openBrowser.setEnabled(false);
		openBrowser.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					openWebpage(new URL(serverURL.getText()));
				} catch (MalformedURLException e1) {
					e1.printStackTrace();
				}
			}
		});

		JButton save = new JButton("Save Config");
		save.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				savePropeties();
			}
		});
		warPath = new JTextField();
		
		DocumentListener docListener2 = new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				updateJDBCurl();
			}

			public void removeUpdate(DocumentEvent e) {
				updateJDBCurl();
			}

			public void insertUpdate(DocumentEvent e) {
				updateJDBCurl();
			}
		};
		
		warPath.addActionListener(new java.awt.event.ActionListener() {
		    public void actionPerformed(java.awt.event.ActionEvent e) {
		    	updateJDBCurl();    
		    }
		});
		
		warPath.getDocument().addDocumentListener(docListener2);
		warPath.setColumns(10);
		fieldMap.put(Field.WAR_PATH, warPath);

		JButton selectWAR = new JButton("Select");

		selectWAR.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent e) {
				JFileChooser chooser = new JFileChooser(jarPath);
				FileNameExtensionFilter filter = new FileNameExtensionFilter("WAR file", "war");
				chooser.setFileFilter(filter);
				int value = chooser.showOpenDialog(null);
				if (value == JFileChooser.APPROVE_OPTION) {
					warPath.setText(chooser.getSelectedFile().getPath());
					updateJDBCurl();
				}
			}
		});

		jdbcURL = new JTextField();
		jdbcURL.setColumns(10);
		fieldMap.put(Field.JDBC_URL, jdbcURL);

		serverURL = new JTextField();
		serverURL.setEditable(false);
		serverURL.setColumns(10);

		dbUser = new JTextField();
		dbUser.setColumns(10);
		dbUser.setText("tree");
		fieldMap.put(Field.DBUSER, dbUser);

		treedbAdmin = new JTextField();
		treedbAdmin.setEditable(false);
		treedbAdmin.setColumns(10);
		treedbAdmin.setText("admin");

		JLabel lblPasswordl = new JLabel("Password");
		lblPasswordl.setFont(new Font("Tahoma", Font.BOLD, 12));

		JLabel lblPassword = new JLabel("Password");
		lblPassword.setFont(new Font("Tahoma", Font.BOLD, 12));

		dbUserPwd = new JPasswordField();
		dbUserPwd.setColumns(10);
		dbUserPwd.setText("db");
		fieldMap.put(Field.DBUSERPWD, dbUser);

		treedbAdminPwd = new JPasswordField();
		treedbAdminPwd.setColumns(10);
		treedbAdminPwd.setText("admin");
		fieldMap.put(Field.ADMINPWD, treedbAdminPwd);

		JLabel lblHttpPport = new JLabel("HTTP Port");
		lblHttpPport.setFont(new Font("Tahoma", Font.BOLD, 12));

		DocumentListener docListener = new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				updateServerURL();
			}

			public void removeUpdate(DocumentEvent e) {
				updateServerURL();
			}

			public void insertUpdate(DocumentEvent e) {
				updateServerURL();
			}
		};
		
	

		httpPort = new JFormattedTextField(new MaskFormatter("#####"));
		httpPort.setColumns(10);
		httpPort.setText("8080");
		fieldMap.put(Field.PORT, httpPort);

		JLabel lblNewLabel = new JLabel("Context");
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 12));

		context = new JTextField();
		context.setEditable(false);
		context.setColumns(10);
		context.setText("TreeDB");

		JLabel lblDatabase = new JLabel("Database");
		lblDatabase.setFont(new Font("Tahoma", Font.BOLD, 12));

		JLabel lblDdl = new JLabel("DDL");
		lblDdl.setFont(new Font("Tahoma", Font.BOLD, 12));

		ddl = new JComboBox();
		ddl.setModel(new DefaultComboBoxModel(new String[] { "VALIDATE", "UPDATE", "CREATE" }));
		ddl.setSelectedIndex(1);

		databaseList = new JComboBox();
		databaseList.setModel(new DefaultComboBoxModel(new String[] { "H2", "MySQL", "Postgres" }));

		persistenceLayerList = new JComboBox();
		persistenceLayerList.setModel(
				new DefaultComboBoxModel(new String[] { "Hibernate", "JPA/EclipseLink", "JPA/HibernateJPA" }));
		persistenceLayerList.setSelectedIndex(1);

		String currentDir = new File(".").getCanonicalPath() + File.separator;
		final File eclispeFile = new File(currentDir + ECLIPSELINK_WAR);
		final File hibernateFile = new File(currentDir + HIBERNATE_WAR);
		if (eclispeFile.exists()) {
			warPath.setText(eclispeFile.getAbsolutePath());
		}

		fieldMap.put(Field.PERSISTENCE, persistenceLayerList);
		persistenceLayerList.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {

				String player = (String) persistenceLayerList.getSelectedItem();
				File fwarPath = new File(warPath.getText());

				try {
					if (!fwarPath.getCanonicalPath().equals(eclispeFile.getCanonicalPath())
							&& !fwarPath.getCanonicalPath().equals(hibernateFile.getCanonicalPath())) {
						return;
					}
				} catch (IOException e1) {
					e1.printStackTrace();
					return;
				}
				if (player.contains("Eclipse")) {
					warPath.setText(eclispeFile.getAbsolutePath());
				} else {
					warPath.setText(hibernateFile.getAbsolutePath());
				}
			}
		});

		ip4List = new JComboBox(ipList.toArray(new String[ipList.size()]));
		fieldMap.put(Field.IP_ADDRESS, ip4List);

		scrollPaneLog = new JScrollPane();

		uiLook = new JCheckBox("Native look");
		uiLook.setFont(new Font("Tahoma", Font.BOLD, 12));
		uiLook.setSelected(true);
		fieldMap.put(Field.UILOOK, uiLook);
		uiLook.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {

					boolean sel = uiLook.isSelected();
					if (sel) {
						UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
					} else {
						UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
					}
					SwingUtilities.updateComponentTreeUI(JettyServer.this);
			
				} catch (Exception e1) {
					e1.printStackTrace();
				}
			}
		});

		GroupLayout groupLayout = new GroupLayout(getContentPane());
		groupLayout
				.setHorizontalGroup(
						groupLayout
								.createParallelGroup(
										Alignment.LEADING)
								.addGroup(
										groupLayout.createSequentialGroup().addContainerGap()
												.addGroup(
														groupLayout.createParallelGroup(Alignment.LEADING)
																.addGroup(
																		groupLayout.createSequentialGroup()
																				.addGroup(groupLayout
																						.createParallelGroup(
																								Alignment.LEADING)
																						.addComponent(startServer)
																						.addComponent(lblWarFile)
																						.addComponent(lblJdbcUrl)
																						.addComponent(lblServerUrl)
																						.addComponent(lblDatabaseUser)
																						.addComponent(lblTreedbAdmin)
																						.addComponent(lblServerIp)
																						.addComponent(
																								lblPersistenceLayer))
								.addPreferredGap(ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
										.addGroup(groupLayout.createSequentialGroup()
												.addComponent(persistenceLayerList, GroupLayout.PREFERRED_SIZE,
														GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
												.addGap(14).addComponent(lblDatabase)
												.addPreferredGap(ComponentPlacement.RELATED)
												.addComponent(databaseList, GroupLayout.PREFERRED_SIZE, 59,
														GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(ComponentPlacement.RELATED).addComponent(lblDdl)
										.addPreferredGap(ComponentPlacement.RELATED).addComponent(ddl,
												GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
												GroupLayout.PREFERRED_SIZE))
										.addGroup(groupLayout.createSequentialGroup().addComponent(stopServer)
												.addPreferredGap(ComponentPlacement.RELATED).addComponent(openBrowser)
												.addPreferredGap(ComponentPlacement.RELATED).addComponent(save))
										.addGroup(groupLayout.createParallelGroup(Alignment.TRAILING, false)
												.addGroup(groupLayout.createSequentialGroup().addGroup(groupLayout
														.createParallelGroup(Alignment.LEADING)
														.addComponent(dbUser, GroupLayout.PREFERRED_SIZE,
																GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
														.addComponent(treedbAdmin, GroupLayout.PREFERRED_SIZE,
																GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
														.addGap(14).addGroup(
																groupLayout.createParallelGroup(Alignment.LEADING)
																		.addGroup(groupLayout.createSequentialGroup()
																				.addComponent(lblPassword)
																				.addPreferredGap(
																						ComponentPlacement.RELATED)
																		.addComponent(treedbAdminPwd,
																				GroupLayout.PREFERRED_SIZE,
																				GroupLayout.DEFAULT_SIZE,
																				GroupLayout.PREFERRED_SIZE))
																.addGroup(groupLayout.createSequentialGroup()
																		.addComponent(lblPasswordl)
																		.addPreferredGap(ComponentPlacement.RELATED)
																		.addComponent(dbUserPwd,
																				GroupLayout.PREFERRED_SIZE,
																				GroupLayout.DEFAULT_SIZE,
																				GroupLayout.PREFERRED_SIZE)
																		.addPreferredGap(ComponentPlacement.RELATED,
																				GroupLayout.DEFAULT_SIZE,
																				Short.MAX_VALUE)
																		.addComponent(uiLook))))
												.addGroup(Alignment.LEADING, groupLayout
														.createParallelGroup(Alignment.LEADING, false)
														.addComponent(serverURL).addComponent(jdbcURL)
														.addGroup(groupLayout.createSequentialGroup()
																.addComponent(warPath, GroupLayout.PREFERRED_SIZE, 341,
																		GroupLayout.PREFERRED_SIZE)
																.addPreferredGap(ComponentPlacement.RELATED)
																.addComponent(selectWAR))
														.addGroup(groupLayout.createSequentialGroup()
																.addComponent(ip4List, GroupLayout.PREFERRED_SIZE, 97,
																		GroupLayout.PREFERRED_SIZE)
																.addPreferredGap(ComponentPlacement.UNRELATED)
																.addComponent(lblHttpPport)
																.addPreferredGap(ComponentPlacement.RELATED)
																.addComponent(httpPort, GroupLayout.PREFERRED_SIZE, 50,
																		GroupLayout.PREFERRED_SIZE)
																.addPreferredGap(ComponentPlacement.RELATED)
																.addComponent(lblNewLabel)
																.addPreferredGap(ComponentPlacement.UNRELATED)
																.addComponent(context, GroupLayout.PREFERRED_SIZE,
																		GroupLayout.DEFAULT_SIZE,
																		GroupLayout.PREFERRED_SIZE)
																.addPreferredGap(ComponentPlacement.RELATED)))))
								.addGap(155)).addGroup(
										groupLayout.createSequentialGroup()
												.addComponent(scrollPaneLog, GroupLayout.PREFERRED_SIZE, 575,
														GroupLayout.PREFERRED_SIZE)
												.addContainerGap(22, Short.MAX_VALUE)))));
		groupLayout.setVerticalGroup(groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup().addContainerGap()
						.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE).addComponent(lblWarFile)
								.addComponent(warPath, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
										GroupLayout.PREFERRED_SIZE)
								.addComponent(selectWAR))
				.addPreferredGap(ComponentPlacement.RELATED)
				.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE).addComponent(lblServerIp)
						.addComponent(lblHttpPport)
						.addComponent(httpPort, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addComponent(ip4List, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addComponent(lblNewLabel).addComponent(context, GroupLayout.PREFERRED_SIZE,
								GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(ComponentPlacement.RELATED)
				.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE).addComponent(lblServerUrl).addComponent(
						serverURL, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(ComponentPlacement.RELATED)
				.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE).addComponent(lblPersistenceLayer)
						.addComponent(persistenceLayerList, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addComponent(ddl, GroupLayout.PREFERRED_SIZE, 17, GroupLayout.PREFERRED_SIZE)
						.addComponent(lblDdl)
						.addComponent(databaseList, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addComponent(lblDatabase))
				.addPreferredGap(ComponentPlacement.RELATED)
				.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE).addComponent(lblJdbcUrl).addComponent(
						jdbcURL, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(ComponentPlacement.RELATED)
				.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE).addComponent(lblDatabaseUser)
						.addComponent(dbUser, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addComponent(lblPasswordl)
						.addComponent(dbUserPwd, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addComponent(uiLook))
				.addPreferredGap(ComponentPlacement.RELATED)
				.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE).addComponent(lblTreedbAdmin)
						.addComponent(treedbAdmin, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addComponent(lblPassword).addComponent(treedbAdminPwd, GroupLayout.PREFERRED_SIZE,
								GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(ComponentPlacement.RELATED)
				.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE).addComponent(startServer)
						.addComponent(stopServer).addComponent(openBrowser).addComponent(save))
				.addPreferredGap(ComponentPlacement.RELATED)
				.addComponent(scrollPaneLog, GroupLayout.PREFERRED_SIZE, 110, GroupLayout.PREFERRED_SIZE)
				.addContainerGap(21, Short.MAX_VALUE)));

		logArea = new JTextArea();
		scrollPaneLog.setViewportView(logArea);

		getContentPane().setLayout(groupLayout);

		JMenuBar menuBar = new JMenuBar();
		setJMenuBar(menuBar);

		mainMenu = new JMenu("Help");
		menuBar.add(mainMenu);

		//
		menuHelp = new JMenuItem("Help");
		menuHelp.setIcon(new ImageIcon(JettyServer.class.getResource("/images/questionmark.png")));
		mainMenu.add(menuHelp);
		menuHelp.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (help == null) {
					help = new HelpWindow("questionmark.png", "Help", "help.html", "server.png");
					help.setSize(700, 430);
				} else {
					if (!help.isVisible()) {
						help.setVisible(true);
					}
					help.toFront();
					help.setState(Frame.NORMAL);
				}
			}
		});

		JMenuItem menuAbout = new JMenuItem("About");
		menuAbout.setIcon(new ImageIcon(JettyServer.class.getResource("/images/info.png")));
		mainMenu.add(menuAbout);
		menuAbout.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (about == null) {
					about = new HelpWindow("info.png", "About", "about.html", "TreeDB.png");
					about.setSize(270, 285);
				} else {
					if (!about.isVisible()) {
						about.setVisible(true);
					}
					about.toFront();
					about.setState(Frame.NORMAL);
				}
			}
		});
		loadProperties();
		updateServerURL();
		updateJDBCurl();
	}

	@SuppressWarnings("rawtypes")
	private void loadProperties() {
		Properties prop = new Properties();
		InputStream input = null;

		try {
			File file = new File(jarPath + "config.properties");
			if (!file.exists()) {
				return;
			}
			input = new FileInputStream(file);
			// load a properties file
			prop.load(input);

			for (Field key : fieldMap.keySet()) {
				String value = prop.getProperty(key.name());
				if (value == null) {
					continue;
				}
				Object o = fieldMap.get(key);
				if (o instanceof JTextField) {
					((JTextField) o).setText(value);
				} else if (o instanceof JComboBox) {
					((JComboBox) o).setSelectedItem(value);
				}

			}

		} catch (IOException ex) {
			ex.printStackTrace();
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

	}

	@SuppressWarnings("rawtypes")
	private void savePropeties() {
		Properties prop = new Properties();
		OutputStream output = null;

		try {
			output = new FileOutputStream(jarPath + "config.properties");
			for (Field key : fieldMap.keySet()) {
				Object o = fieldMap.get(key);
				String value = "";
				if (o instanceof JTextField) {
					value = ((JTextField) o).getText();
				} else if (o instanceof JComboBox) {
					value = (String) ((JComboBox) o).getSelectedItem();
				} else {
					continue;
				}
				prop.setProperty(key.name(), value);
			}
			prop.store(output, null);

		} catch (IOException io) {
			io.printStackTrace();
		} finally {
			if (output != null) {
				try {
					output.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

		}
	}
}
