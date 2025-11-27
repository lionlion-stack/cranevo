const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

console.log('=== ENVIRONMENT CHECK ===');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('JWT_SECRET exists:', !!process.env.JWT_SECRET);
console.log('MONGODB_URI:', process.env.MONGODB_URI ? 'Set' : 'NOT SET');
console.log('PORT:', process.env.PORT);

// Middleware - Updated CORS for production
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? true  // Allow all origins in production (you can restrict this later)
    : ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5000'],
  credentials: true
}));
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// MongoDB Connection - Updated for production
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/cranevo';
mongoose.connect(MONGODB_URI);

mongoose.connection.on('connected', () => {
  console.log('✅ Connected to MongoDB successfully');
});

mongoose.connection.on('error', (err) => {
  console.log('❌ MongoDB connection error:', err);
});

// Database Models
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  countryCode: { type: String, required: true },
  phone: { type: String, required: true },
  company: { type: String, default: '' },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  createdAt: { type: Date, default: Date.now }
});

const ListingSchema = new mongoose.Schema({
  title: { type: String, required: true },
  category: { 
    type: String, 
    required: true,
    enum: ['cranes', 'forklifts', 'trucks', 'excavators', 'loaders', 'other']
  },
  price: { type: Number, required: true },
  description: { type: String, required: true },
  year: { type: Number, required: true },
  hours: { type: Number, default: 0 },
  capacity: { type: Number, default: 0 },
  boomLength: { type: Number, default: 0 },
  location: { type: String, required: true },
  status: { 
    type: String, 
    default: 'available',
    enum: ['available', 'sold', 'reserved']
  },
  images: [{ type: String }],
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

const InquirySchema = new mongoose.Schema({
  listingId: { type: mongoose.Schema.Types.ObjectId, ref: 'Listing', required: true },
  buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  message: { type: String, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'contacted', 'negotiating', 'completed', 'cancelled'],
    default: 'pending'
  },
  commissionRate: { type: Number, default: 0.05 },
  adminNotes: { type: String },
  finalSalePrice: { type: Number },
  commissionAmount: { type: Number },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  completedAt: { type: Date }
});

const User = mongoose.model('User', UserSchema);
const Listing = mongoose.model('Listing', ListingSchema);
const Inquiry = mongoose.model('Inquiry', InquirySchema);

// JWT Secret from environment variables - SECURE
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('❌ ERROR: JWT_SECRET not set in environment variables!');
  console.error('Please set JWT_SECRET in your .env file');
  process.exit(1);
}

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'No token, authorization denied' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ message: 'Token is not valid' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Admin Middleware
const adminMiddleware = async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    next();
  } catch (error) {
    res.status(403).json({ message: 'Admin access required' });
  }
};

// Create default admin user on startup
const createDefaultAdmin = async () => {
  try {
    const adminExists = await User.findOne({ email: 'admin@cranevo.com' });
    if (!adminExists) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('admin123', salt);
      
      const adminUser = new User({
        name: 'Cranevo Admin',
        email: 'admin@cranevo.com',
        password: hashedPassword,
        countryCode: '+961',
        phone: '71054221',
        company: 'Cranevo',
        role: 'admin'
      });
      
      await adminUser.save();
      console.log('✅ Default admin user created: admin@cranevo.com / admin123');
    }
  } catch (error) {
    console.log('❌ Error creating default admin:', error);
  }
};

// Country codes data
const countryCodes = [
  { code: '+961', name: 'Lebanon', flag: '🇱🇧' },
  { code: '+1', name: 'United States', flag: '🇺🇸' },
  { code: '+44', name: 'United Kingdom', flag: '🇬🇧' },
  { code: '+61', name: 'Australia', flag: '🇦🇺' },
  { code: '+49', name: 'Germany', flag: '🇩🇪' },
  { code: '+33', name: 'France', flag: '🇫🇷' },
  { code: '+81', name: 'Japan', flag: '🇯🇵' },
  { code: '+86', name: 'China', flag: '🇨🇳' },
  { code: '+91', name: 'India', flag: '🇮🇳' },
  { code: '+7', name: 'Russia', flag: '🇷🇺' },
  { code: '+55', name: 'Brazil', flag: '🇧🇷' },
  { code: '+34', name: 'Spain', flag: '🇪🇸' },
  { code: '+39', name: 'Italy', flag: '🇮🇹' },
  { code: '+82', name: 'South Korea', flag: '🇰🇷' },
  { code: '+52', name: 'Mexico', flag: '🇲🇽' },
  { code: '+31', name: 'Netherlands', flag: '🇳🇱' },
  { code: '+41', name: 'Switzerland', flag: '🇨🇭' },
  { code: '+46', name: 'Sweden', flag: '🇸🇪' },
  { code: '+47', name: 'Norway', flag: '🇳🇴' },
  { code: '+45', name: 'Denmark', flag: '🇩🇰' },
  { code: '+358', name: 'Finland', flag: '🇫🇮' },
  { code: '+32', name: 'Belgium', flag: '🇧🇪' },
  { code: '+351', name: 'Portugal', flag: '🇵🇹' },
  { code: '+353', name: 'Ireland', flag: '🇮🇪' },
  { code: '+43', name: 'Austria', flag: '🇦🇹' },
  { code: '+48', name: 'Poland', flag: '🇵🇱' },
  { code: '+420', name: 'Czech Republic', flag: '🇨🇿' },
  { code: '+36', name: 'Hungary', flag: '🇭🇺' },
  { code: '+40', name: 'Romania', flag: '🇷🇴' },
  { code: '+30', name: 'Greece', flag: '🇬🇷' },
  { code: '+90', name: 'Turkey', flag: '🇹🇷' },
  { code: '+966', name: 'Saudi Arabia', flag: '🇸🇦' },
  { code: '+971', name: 'United Arab Emirates', flag: '🇦🇪' },
  { code: '+20', name: 'Egypt', flag: '🇪🇬' },
  { code: '+27', name: 'South Africa', flag: '🇿🇦' },
  { code: '+234', name: 'Nigeria', flag: '🇳🇬' },
  { code: '+254', name: 'Kenya', flag: '🇰🇪' },
  { code: '+65', name: 'Singapore', flag: '🇸🇬' },
  { code: '+60', name: 'Malaysia', flag: '🇲🇾' },
  { code: '+66', name: 'Thailand', flag: '🇹🇭' },
  { code: '+84', name: 'Vietnam', flag: '🇻🇳' },
  { code: '+62', name: 'Indonesia', flag: '🇮🇩' },
  { code: '+63', name: 'Philippines', flag: '🇵🇭' },
  { code: '+64', name: 'New Zealand', flag: '🇳🇿' },
  { code: '+54', name: 'Argentina', flag: '🇦🇷' },
  { code: '+56', name: 'Chile', flag: '🇨🇱' },
  { code: '+57', name: 'Colombia', flag: '🇨🇴' },
  { code: '+51', name: 'Peru', flag: '🇵🇪' },
  { code: '+58', name: 'Venezuela', flag: '🇻🇪' },
  { code: '+593', name: 'Ecuador', flag: '🇪🇨' },
  { code: '+507', name: 'Panama', flag: '🇵🇦' },
  { code: '+506', name: 'Costa Rica', flag: '🇨🇷' },
  { code: '+1', name: 'Canada', flag: '🇨🇦' }
];

// Routes

// Get country codes
app.get('/api/country-codes', (req, res) => {
  res.json({ countryCodes });
});

// User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, countryCode, phone, company } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      countryCode,
      phone,
      company
    });

    await user.save();

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        countryCode: user.countryCode,
        phone: user.phone,
        company: user.company,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        countryCode: user.countryCode,
        phone: user.phone,
        company: user.company,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Get user profile
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        countryCode: req.user.countryCode,
        phone: req.user.phone,
        company: req.user.company,
        role: req.user.role
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user profile
app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const { name, countryCode, phone, company } = req.body;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { name, countryCode, phone, company },
      { new: true }
    ).select('-password');

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        countryCode: user.countryCode,
        phone: user.phone,
        company: user.company,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create listing
app.post('/api/listings', authMiddleware, upload.array('images', 10), async (req, res) => {
  try {
    const {
      title,
      category,
      price,
      description,
      year,
      hours,
      capacity,
      boomLength,
      location
    } = req.body;

    const images = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];

    const listing = new Listing({
      title,
      category,
      price: parseFloat(price),
      description,
      year: parseInt(year),
      hours: hours ? parseInt(hours) : 0,
      capacity: capacity ? parseFloat(capacity) : 0,
      boomLength: boomLength ? parseFloat(boomLength) : 0,
      location,
      images,
      userId: req.user._id
    });

    await listing.save();
    
    await listing.populate('userId', 'name email phone company');

    res.status(201).json({
      message: 'Listing created successfully',
      listing
    });
  } catch (error) {
    console.error('Create listing error:', error);
    res.status(500).json({ message: 'Server error while creating listing' });
  }
});

// Get all listings with filters
app.get('/api/listings', async (req, res) => {
  try {
    const { category, status, userId, page = 1, limit = 12 } = req.query;
    
    const filter = {};
    if (category && category !== 'all') filter.category = category;
    if (status && status !== 'all') filter.status = status;
    if (userId) filter.userId = userId;

    const listings = await Listing.find(filter)
      .populate('userId', 'name email phone company')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Listing.countDocuments(filter);

    res.json({
      listings,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Get listings error:', error);
    res.status(500).json({ message: 'Server error while fetching listings' });
  }
});

// Get single listing
app.get('/api/listings/:id', async (req, res) => {
  try {
    const listing = await Listing.findById(req.params.id)
      .populate('userId', 'name email phone company countryCode');

    if (!listing) {
      return res.status(404).json({ message: 'Listing not found' });
    }

    res.json({ listing });
  } catch (error) {
    console.error('Get listing error:', error);
    res.status(500).json({ message: 'Server error while fetching listing' });
  }
});

// Update listing status
app.patch('/api/listings/:id/status', authMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    
    const listing = await Listing.findById(req.params.id);
    
    if (!listing) {
      return res.status(404).json({ message: 'Listing not found' });
    }

    if (listing.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Not authorized to update this listing' });
    }

    listing.status = status;
    await listing.save();

    res.json({
      message: 'Listing status updated successfully',
      listing
    });
  } catch (error) {
    console.error('Update listing status error:', error);
    res.status(500).json({ message: 'Server error while updating listing status' });
  }
});

// Delete listing
app.delete('/api/listings/:id', authMiddleware, async (req, res) => {
  try {
    const listing = await Listing.findById(req.params.id);
    
    if (!listing) {
      return res.status(404).json({ message: 'Listing not found' });
    }

    if (listing.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Not authorized to delete this listing' });
    }

    // Delete associated images
    if (listing.images && listing.images.length > 0) {
      listing.images.forEach(image => {
        const imagePath = path.join(__dirname, image);
        if (fs.existsSync(imagePath)) {
          fs.unlinkSync(imagePath);
        }
      });
    }

    await Listing.findByIdAndDelete(req.params.id);

    res.json({ message: 'Listing deleted successfully' });
  } catch (error) {
    console.error('Delete listing error:', error);
    res.status(500).json({ message: 'Server error while deleting listing' });
  }
});

// Get user's listings
app.get('/api/my-listings', authMiddleware, async (req, res) => {
  try {
    const listings = await Listing.find({ userId: req.user._id })
      .populate('userId', 'name email phone company')
      .sort({ createdAt: -1 });

    res.json({ listings });
  } catch (error) {
    console.error('Get my listings error:', error);
    res.status(500).json({ message: 'Server error while fetching your listings' });
  }
});

// Search listings
app.get('/api/search', async (req, res) => {
  try {
    const { q, category, minPrice, maxPrice, location } = req.query;
    
    const filter = {};
    
    if (q) {
      filter.$or = [
        { title: { $regex: q, $options: 'i' } },
        { description: { $regex: q, $options: 'i' } },
        { location: { $regex: q, $options: 'i' } }
      ];
    }
    
    if (category && category !== 'all') filter.category = category;
    if (location) filter.location = { $regex: location, $options: 'i' };
    
    if (minPrice || maxPrice) {
      filter.price = {};
      if (minPrice) filter.price.$gte = parseFloat(minPrice);
      if (maxPrice) filter.price.$lte = parseFloat(maxPrice);
    }

    const listings = await Listing.find(filter)
      .populate('userId', 'name email phone company')
      .sort({ createdAt: -1 })
      .limit(20);

    res.json({ listings });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ message: 'Server error while searching' });
  }
});

// Create inquiry
app.post('/api/inquiries', authMiddleware, async (req, res) => {
  try {
    const { listingId, message } = req.body;

    const listing = await Listing.findById(listingId).populate('userId');
    if (!listing) {
      return res.status(404).json({ message: 'Listing not found' });
    }

    const inquiry = new Inquiry({
      listingId,
      buyerId: req.user._id,
      sellerId: listing.userId,
      message,
      commissionRate: 0.05 // 5% commission charged to SELLER
    });

    await inquiry.save();
    
    await inquiry.populate('buyerId', 'name email phone countryCode company');
    await inquiry.populate('sellerId', 'name email phone countryCode company');
    await inquiry.populate('listingId');

    res.status(201).json({
      message: 'Inquiry submitted successfully! We will contact you shortly.',
      inquiry
    });
  } catch (error) {
    console.error('Inquiry error:', error);
    res.status(500).json({ message: 'Error submitting inquiry' });
  }
});

// Get inquiries for admin
app.get('/api/admin/inquiries', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const inquiries = await Inquiry.find()
      .populate('buyerId', 'name email phone countryCode company')
      .populate('sellerId', 'name email phone countryCode company')
      .populate('listingId')
      .sort({ createdAt: -1 });

    res.json({ inquiries });
  } catch (error) {
    console.error('Get inquiries error:', error);
    res.status(500).json({ message: 'Error fetching inquiries' });
  }
});

// Update inquiry status
app.patch('/api/admin/inquiries/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { status, adminNotes, finalSalePrice } = req.body;

    const updateData = { 
      status, 
      adminNotes, 
      updatedAt: new Date()
    };

    // If marking as completed and final sale price is provided, calculate commission
    if (status === 'completed' && finalSalePrice) {
      const commissionAmount = finalSalePrice * 0.05; // 5% commission
      updateData.finalSalePrice = finalSalePrice;
      updateData.commissionAmount = commissionAmount;
      updateData.completedAt = new Date();

      // Also update the listing status to sold
      await Listing.findByIdAndUpdate(
        req.body.listingId, 
        { status: 'sold' }
      );
    }

    const inquiry = await Inquiry.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    )
    .populate('buyerId', 'name email phone countryCode company')
    .populate('sellerId', 'name email phone countryCode company')
    .populate('listingId');

    if (!inquiry) {
      return res.status(404).json({ message: 'Inquiry not found' });
    }

    res.json({
      message: 'Inquiry updated successfully',
      inquiry
    });
  } catch (error) {
    console.error('Update inquiry error:', error);
    res.status(500).json({ message: 'Error updating inquiry' });
  }
});

// Calculate commission for completed sale
app.post('/api/admin/calculate-commission', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { finalSalePrice } = req.body;

    const commission = finalSalePrice * 0.05; // 5% commission
    const sellerReceives = finalSalePrice - commission;

    res.json({
      finalSalePrice,
      commissionRate: 5,
      commissionAmount: commission,
      sellerReceives: sellerReceives,
      breakdown: {
        salePrice: finalSalePrice,
        commission: commission,
        netToSeller: sellerReceives
      }
    });
  } catch (error) {
    console.error('Commission calculation error:', error);
    res.status(500).json({ message: 'Error calculating commission' });
  }
});

// Get admin dashboard stats
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalListings = await Listing.countDocuments();
    const totalInquiries = await Inquiry.countDocuments();
    const completedInquiries = await Inquiry.countDocuments({ status: 'completed' });
    
    // Calculate total commission
    const completedSales = await Inquiry.find({ status: 'completed' });
    const totalCommission = completedSales.reduce((sum, inquiry) => sum + (inquiry.commissionAmount || 0), 0);

    // Recent activities
    const recentInquiries = await Inquiry.find()
      .populate('buyerId', 'name')
      .populate('listingId', 'title')
      .sort({ createdAt: -1 })
      .limit(5);

    res.json({
      stats: {
        totalUsers,
        totalListings,
        totalInquiries,
        completedInquiries,
        totalCommission
      },
      recentActivities: recentInquiries
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ message: 'Error fetching admin stats' });
  }
});

// Get all users for admin
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find()
      .select('-password')
      .sort({ createdAt: -1 });

    res.json({ users });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Error fetching users' });
  }
});

// Get all listings for admin
app.get('/api/admin/listings', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const listings = await Listing.find()
      .populate('userId', 'name email phone company')
      .sort({ createdAt: -1 });

    res.json({ listings });
  } catch (error) {
    console.error('Get listings error:', error);
    res.status(500).json({ message: 'Error fetching listings' });
  }
});

// Delete user (admin only)
app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Prevent admin from deleting themselves
    if (user._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ message: 'Cannot delete your own account' });
    }

    // Delete user's listings and inquiries
    await Listing.deleteMany({ userId: user._id });
    await Inquiry.deleteMany({ $or: [{ buyerId: user._id }, { sellerId: user._id }] });

    await User.findByIdAndDelete(req.params.id);

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ message: 'Error deleting user' });
  }
});

// Delete listing (admin only)
app.delete('/api/admin/listings/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const listing = await Listing.findById(req.params.id);
    
    if (!listing) {
      return res.status(404).json({ message: 'Listing not found' });
    }

    // Delete associated images
    if (listing.images && listing.images.length > 0) {
      listing.images.forEach(image => {
        const imagePath = path.join(__dirname, image);
        if (fs.existsSync(imagePath)) {
          fs.unlinkSync(imagePath);
        }
      });
    }

    // Delete associated inquiries
    await Inquiry.deleteMany({ listingId: listing._id });

    await Listing.findByIdAndDelete(req.params.id);

    res.json({ message: 'Listing deleted successfully' });
  } catch (error) {
    console.error('Delete listing error:', error);
    res.status(500).json({ message: 'Error deleting listing' });
  }
});

// Health check route
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Cranevo API is running',
    timestamp: new Date().toISOString()
  });
});

// Serve frontend in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../frontend')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'index.html'));
  });
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  await createDefaultAdmin();
  console.log(`🚀 Cranevo Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🗄️ MongoDB: ${MONGODB_URI}`);
  console.log(`👤 Default admin: admin@cranevo.com / admin123`);
  console.log(`✅ Health check: http://localhost:${PORT}/api/health`);
});
